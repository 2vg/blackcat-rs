extern crate wuhu;

use wuhu::str;

#[test]
fn concat() {
    let h = "hello";
    let w = "world";

    // create null-terminated Vec
    let hw_c_char = "helloworld\u{0000}"
        .to_string()
        .chars()
        .map(|c| c as i8)
        .collect::<Vec<i8>>();

    // test concat for c_char
    let dst = str::to_c_char(w);
    assert_eq!(hw_c_char, str::concat(h, dst.as_ptr() as _));

    let hw_wide = "helloworld\u{0000}"
        .to_string()
        .chars()
        .map(|c| c as u16)
        .collect::<Vec<_>>();

    // test concat for windows wide string
    let dst = str::to_wide(w);
    assert_eq!(hw_wide, str::concat_wide(h, dst.as_ptr() as _));
}

#[test]
fn compare() {
    let x = "apple";
    let y = "apple\u{0000}";

    assert_eq!(true, str::compare(x, y.as_ptr() as _));
    assert_eq!(true, str::compare_wide(x, str::to_wide(y).as_ptr() as _));
}
