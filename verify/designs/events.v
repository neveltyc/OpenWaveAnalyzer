module events;
  reg clk = 0;
  event trigger_a, trigger_b, trigger_c;
  reg [7:0] count = 0;

  always #5 clk = ~clk;

  initial begin
    $dumpfile("events.vcd");
    $dumpvars(0, events);
    #10 -> trigger_a;
    #10 -> trigger_b;
    #10 -> trigger_a;
    #10 -> trigger_c;
    #10 -> trigger_b;
    #10 -> trigger_a;
    #10 -> trigger_c;
    #20 $finish;
  end

  always @(posedge clk) begin
    count <= count + 1;
  end

  always @(trigger_a) count <= count + 2;
  always @(trigger_b) count <= count + 4;
  always @(trigger_c) count <= count + 8;
endmodule
