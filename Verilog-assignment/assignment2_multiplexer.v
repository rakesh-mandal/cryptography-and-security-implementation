// Assignment 2: 2-to-1 Multiplexer (design + testbench)
`timescale 1ns/1ps

module multiplexer (
    input  datain_0,
    input  datain_1,
    input  sel,
    output mux_out
);
    assign mux_out = sel ? datain_1 : datain_0;
endmodule

module tb_multiplexer;
    reg datain_0, datain_1, sel;
    wire mux_out;
    integer i;

    multiplexer uut (
        .datain_0(datain_0),
        .datain_1(datain_1),
        .sel(sel),
        .mux_out(mux_out)
    );

    initial begin
        $display("datain_0 datain_1 sel | mux_out");
        $display("--------------------------------");

        for (i = 0; i < 8; i = i + 1) begin
            {datain_0, datain_1, sel} = i;
            #10;
            $display("%b %b %b | %b", datain_0, datain_1, sel, mux_out);
        end

        $finish;
    end
endmodule
