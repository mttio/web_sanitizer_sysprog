// This script contains eval, which should be blocked by the JS sanitizer
let code = "alert(1)";
eval(code);
