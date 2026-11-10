// Assignment 1: Full Adder (design + testbench)
module full_adder (
    input  a,
    input  b,
    input  carryin,
    output sum,
    output carryout
);
    assign sum      = a ^ b ^ carryin;
    assign carryout = (a & b) | (b & carryin) | (a & carryin);
endmodule

module tb_full_adder;
    reg a, b, carryin;
    wire sum, carryout;
    integer i;

    full_adder uut (
        .a(a),
        .b(b),
        .carryin(carryin),
        .sum(sum),
        .carryout(carryout)
    );

    initial begin
        $display("Full Adder Truth Table");
        $display("-------------------------------");
        $display("a b carryin | sum carryout");

        for (i = 0; i < 8; i = i + 1) begin
            {a, b, carryin} = i;
            #10;
            $display("%b %b %b | %b %b", a, b, carryin, sum, carryout);
        end

        $finish;
    end
endmodule
