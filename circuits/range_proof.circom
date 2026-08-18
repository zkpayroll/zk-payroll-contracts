pragma circom 2.0.0;

template Num2Bits(n) {
    signal input in;
    signal output out[n];

    var lc = 0;
    var e2 = 1;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc += out[i] * e2;
        e2 = e2 + e2;
    }

    lc === in;
}

template SalaryRangeProof() {
    signal input salary;

    component bits = Num2Bits(64);
    bits.in <== salary;
}
