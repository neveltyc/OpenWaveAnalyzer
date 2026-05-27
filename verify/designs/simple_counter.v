module simple_counter;
  reg clk = 0;
  reg rst_n = 0;
  reg [7:0] counter = 0;
  reg [3:0] state = 0;
  reg flag = 0;

  always #5 clk = ~clk;

  initial begin
    $dumpfile("simple.vcd");
    $dumpvars(0, simple_counter);
    #2 rst_n = 1;
    #100 $finish;
  end

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      counter <= 0;
      state <= 0;
      flag <= 0;
    end else begin
      counter <= counter + 1;
      if (counter == 8'd10) state <= 1;
      if (counter == 8'd20) state <= 2;
      if (counter == 8'd30) state <= 3;
      flag <= (counter[2:0] == 3'b111);
    end
  end
endmodule
