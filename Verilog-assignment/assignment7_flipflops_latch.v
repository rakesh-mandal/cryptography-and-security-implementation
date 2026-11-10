// Assignment 7: D flip-flops and latch (design + testbench)
`timescale 1ns/1ps
`define DELAY #2 // Flip-flop delay

// 1. Rising edge, simple
module dff_rise_simple (d, clk, q);
    input d, clk;
    output q;
    reg q;
    always @(posedge clk) begin
        q <= `DELAY d;
    end
endmodule

// 2. Rising edge, synchronous reset (active high)
module dff_rise_sync_rst (d, clk, reset, q);
    input d, clk, reset;
    output q;
    reg q;
    always @(posedge clk) begin
        if (reset) q <= 0;
        else       q <= `DELAY d;
    end
endmodule

// 3. Rising edge, asynchronous reset, active high
module dflipflop (d, clk, reset, q);
    input d, clk, reset;
    output q;
    reg q;
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            q <= 0;
        end
        else begin
            q <= `DELAY d;
        end
    end
endmodule

// 4. Rising edge, asynchronous reset, active low
module dff_rise_async_rst_low (d, clk, reset_n, q);
    input d, clk, reset_n;
    output q;
    reg q;
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) q <= 0;
        else          q <= `DELAY d;
    end
endmodule

// 5. Falling edge, simple
module dff_fall_simple (d, clk, q);
    input d, clk;
    output q;
    reg q;
    always @(negedge clk) begin
        q <= `DELAY d;
    end
endmodule

// 6. Falling edge, synchronous reset (active high)
module dff_fall_sync_rst (d, clk, reset, q);
    input d, clk, reset;
    output q;
    reg q;
    always @(negedge clk) begin
        if (reset) q <= 0;
        else       q <= `DELAY d;
    end
endmodule

// 7. Falling edge, asynchronous reset, active high
module dff_fall_async_rst_high (d, clk, reset, q);
    input d, clk, reset;
    output q;
    reg q;
    always @(negedge clk or posedge reset) begin
        if (reset) q <= 0;
        else       q <= `DELAY d;
    end
endmodule

// 8. Falling edge, asynchronous reset, active low
module dff_fall_async_rst_low (d, clk, reset_n, q);
    input d, clk, reset_n;
    output q;
    reg q;
    always @(negedge clk or negedge reset_n) begin
        if (!reset_n) q <= 0;
        else          q <= `DELAY d;
    end
endmodule

// 9. Latch (transparent while en = 1)
module d_latch (d, en, q);
    input d, en;
    output q;
    reg q;
    always @(d or en) begin
        if (en) q <= d;
    end
endmodule

// ---------------- Testbench ----------------
module tb_flipflops;

    reg d, clk, reset, reset_n, en;

    wire q_r_simple, q_r_sync, q_r_async_hi, q_r_async_lo;
    wire q_f_simple, q_f_sync, q_f_async_hi, q_f_async_lo;
    wire q_latch;

    dff_rise_simple         u1 (d, clk, q_r_simple);
    dff_rise_sync_rst       u2 (d, clk, reset, q_r_sync);
    dflipflop               u3 (d, clk, reset, q_r_async_hi);
    dff_rise_async_rst_low  u4 (d, clk, reset_n, q_r_async_lo);
    dff_fall_simple         u5 (d, clk, q_f_simple);
    dff_fall_sync_rst       u6 (d, clk, reset, q_f_sync);
    dff_fall_async_rst_high u7 (d, clk, reset, q_f_async_hi);
    dff_fall_async_rst_low  u8 (d, clk, reset_n, q_f_async_lo);
    d_latch                 u9 (d, en, q_latch);

    // Clock generation: 10 ns period
    initial clk = 0;
    always #5 clk = ~clk;

    initial begin
        d = 0;
        reset = 0;
        reset_n = 1;
        en = 0;

        $display("Time | clk d rst rst_n en | R_simple R_sync R_aH R_aL | F_simple F_sync F_aH F_aL | Latch");

        $monitor("%4t | %b %b %b %b %b | %b %b %b %b | %b %b %b %b | %b",
                 $time, clk, d, reset, reset_n, en,
                 q_r_simple, q_r_sync, q_r_async_hi, q_r_async_lo,
                 q_f_simple, q_f_sync, q_f_async_hi, q_f_async_lo,
                 q_latch);

        // Test data
        #2  d = 1;

        #10 d = 0;
            en = 1;

        #5  d = 1;

        #3  en = 0;

        // Active-high reset test
        #2  reset = 1;

        #10 reset = 0;

        // Active-low reset test
        #5  reset_n = 0;

        #10 reset_n = 1;

        // Latch test
        #5  en = 1;
            d = 0;

        #5  en = 0;
            d = 1;

        #5  en = 1;
            d = 0;

        #5  en = 0;

        #10 $finish;
    end

endmodule
