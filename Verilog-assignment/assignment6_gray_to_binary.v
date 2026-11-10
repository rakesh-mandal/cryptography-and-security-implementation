// Assignment 6: 4-bit Gray to Binary Converter (design + testbench)
`timescale 1ns/1ps

module GraytoBin1 (
    input  [3:0] gray, // g3 g2 g1 g0
    output [3:0] bin   // b3 b2 b1 b0
);
    assign bin[3] = gray[3];        // b3 = g3

    xor (bin[2], bin[3], gray[2]);  // b2 = b3 ^ g2
    xor (bin[1], bin[2], gray[1]);  // b1 = b2 ^ g1
    xor (bin[0], bin[1], gray[0]);  // b0 = b1 ^ g0
endmodule

module tb_GraytoBin1;
    reg  [3:0] gray;
    wire [3:0] bin;
    integer i;

    GraytoBin1 uut (
        .gray(gray),
        .bin(bin)
    );

    initial begin
        $display("Gray | Binary");
        $display("-------------");

        for (i = 0; i < 16; i = i + 1) begin
            gray = i;
            #10;
            $display("%b | %b", gray, bin);
        end

        $finish;
    end
endmodule
