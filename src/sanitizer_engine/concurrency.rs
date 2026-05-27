use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

struct PoolState {
    queue: Mutex<VecDeque<Job>>,
    condvar: Condvar,
    shutdown: Mutex<bool>,
}

pub struct ThreadPool {
    workers: Vec<Worker>,
    state: Arc<PoolState>,
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl ThreadPool {

    // Create a new ThreadPool with the specified number of worker threads.
    pub fn new(size: usize) -> Self {
        // Panics if size is 0.
        assert!(size > 0, "ThreadPool size must be greater than zero");

        let state = Arc::new(PoolState {
            queue: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
            shutdown: Mutex::new(false),
        });

        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&state)));
        }

        ThreadPool { workers, state }
    }

    // Enqueue a job for execution by the thread pool.
    pub fn push_job<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut queue = self.state.queue.lock().unwrap();
        // If the pool is shutting down, we should not accept new jobs
        if *self.state.shutdown.lock().unwrap() {
            return;
        }
        queue.push_back(Box::new(f));
        self.state.condvar.notify_one();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        {
            let mut shutdown = self.state.shutdown.lock().unwrap();
            *shutdown = true;
        }
        // Wake up all workers so they can see the shutdown flag
        self.state.condvar.notify_all();

        // Wait for all worker threads to finish processing their current/queued tasks and exit
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

impl Worker {
    fn new(id: usize, state: Arc<PoolState>) -> Self {
        let thread = thread::spawn(move || loop {
            let mut queue_guard = state.queue.lock().unwrap();

            // Wait until there is a job or a shutdown request
            while queue_guard.is_empty() && !*state.shutdown.lock().unwrap() {
                queue_guard = state.condvar.wait(queue_guard).unwrap();
            }

            // If the pool is shutting down and the queue is empty, exit the thread
            if *state.shutdown.lock().unwrap() && queue_guard.is_empty() {
                return;
            }

            // Pop and execute the job
            if let Some(job) = queue_guard.pop_front() {
                drop(queue_guard);
                job();
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_thread_pool_basic_execution() {
        let pool = ThreadPool::new(4);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..10 {
            let counter = Arc::clone(&counter);
            pool.push_job(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            });
        }

        // Drop the pool, which joins all worker threads after executing all enqueued jobs
        drop(pool);

        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn test_thread_pool_concurrency() {
        let pool = ThreadPool::new(2);
        let counter = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(2));

        for _ in 0..2 {
            let counter = Arc::clone(&counter);
            let barrier = Arc::clone(&barrier);
            pool.push_job(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                barrier.wait();
            });
        }

        drop(pool);

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
