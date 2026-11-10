// Assignment 5: 4-to-1 Multiplexer using array indexing (design + testbench)
`timescale 1ns/1ps

module multiplexer (
    input  [3:0] data,
    input  [1:0] sel,
    output       mux_out
);
    assign mux_out = data[sel];
endmodule

module tb_multiplexer;
    reg  [3:0] data;
    reg  [1:0] sel;
    wire       mux_out;
    integer i, j;

    multiplexer uut (
        .data(data),
        .sel(sel),
        .mux_out(mux_out)
    );

    initial begin
        $display("Data Sel | mux_out");
        $display("--------------------");

        for (i = 0; i < 16; i = i + 1) begin
            for (j = 0; j < 4; j = j + 1) begin
                data = i;
                sel  = j;
                #10;
                $display("%b %b | %b", data, sel, mux_out);
            end
        end

        $finish;
    end
endmodule
