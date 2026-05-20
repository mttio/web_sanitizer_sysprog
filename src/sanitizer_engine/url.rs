use url::{Host, Url};

fn check_domain(url: &Url) {
    if let Some(Host::Domain(domain, original)) = url.host() {
        let (domain, original): (Vec<_>, Vec<_>) = domain
            .split('.')
            .zip(original.split('.'))
            .map(|(parsed, original)| {
                if let Some(parsed) = parsed.strip_prefix("xn--") {
                    let mut result1 = "\x1b[92;1mxn\x1b[39;2m--\x1b[0m".to_owned();
                    let mut result = String::new();
                    let mut original = original.chars();

                    'outer: for p in parsed.chars() {
                        for o in original.by_ref() {
                            if o == p {
                                result.push(o);
                                result1.push(p);
                                continue 'outer;
                            } else if o.to_ascii_lowercase() == p {
                                result.push_str("\x1b[95;1m");
                                result.push(o);
                                result.push_str("\x1b[0m");

                                result1.push_str("\x1b[96;1m");
                                result1.push(p);
                                result1.push_str("\x1b[0m");
                                continue 'outer;
                            } else {
                                result.push_str("\x1b[91;1m");
                                result.push(o);
                                result.push_str("\x1b[0m");
                            }
                        }

                        if p == '-' {
                            result1.push_str("\x1b[2;1m");
                        } else {
                            result1.push_str("\x1b[92;1m");
                        }
                        result1.push(p);
                        result1.push_str("\x1b[0m");
                    }
                    (result1, result)
                } else {
                    let mut result1 = String::new();
                    let mut result = String::new();

                    for (o, p) in original.chars().zip(parsed.chars()) {
                        if o.is_ascii_uppercase() {
                            result.push_str("\x1b[95;1m");
                            result.push(o);
                            result.push_str("\x1b[0m");

                            result1.push_str("\x1b[96;1m");
                            result1.push(p);
                            result1.push_str("\x1b[0m");
                        } else {
                            result.push(o);
                            result1.push(p);
                        }
                    }
                    (result1, result)
                }
            })
            .unzip();

        let domain = domain.join(".");
        let original = original.join(".");

        println!("\n{domain}\n{original}\n");
    }
}
