// Assignment 3: 2-to-4 Decoder using gate primitives (design + testbench)
`timescale 1ns/1ps

module decoder_2to4 (
    input  a,
    input  b,
    output y0,
    output y1,
    output y2,
    output y3
);
    wire a_n, b_n;

    not (a_n, a);
    not (b_n, b);

    and (y0, a_n, b_n); // a=0, b=0
    and (y1, a_n, b);   // a=0, b=1
    and (y2, a,   b_n); // a=1, b=0
    and (y3, a,   b);   // a=1, b=1
endmodule

module tb_decoder_2to4;
    reg a, b;
    wire y0, y1, y2, y3;
    integer i;

    decoder_2to4 uut (
        .a(a), .b(b),
        .y0(y0), .y1(y1), .y2(y2), .y3(y3)
    );

    initial begin
        $display("a b | y0 y1 y2 y3");
        $display("------------------");

        for (i = 0; i < 4; i = i + 1) begin
            {a, b} = i;
            #10;
            $display("%b %b | %b %b %b %b", a, b, y0, y1, y2, y3);
        end

        $finish;
    end
endmodule
