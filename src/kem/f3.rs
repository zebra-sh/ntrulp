pub fn freeze(a: i32) -> i8 {
    let b = a - (3 * ((10923 * a) >> 15));
    let c = b - (3 * ((89_478_485 * b + 134_217_728) >> 28));

    c as i8
}
