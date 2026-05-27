module top;
  reg clk = 0;
  always #5 clk = ~clk;

  initial begin
    $dumpfile("nested.vcd");
    $dumpvars(0, top);
    #100 $finish;
  end

  wire [7:0] top_data;
  wire top_valid;
  wire top_ready;

  sub_module u_sub (
    .clk(clk),
    .data_out(top_data),
    .valid_out(top_valid),
    .ready_in(top_ready)
  );

  consumer u_consumer (
    .clk(clk),
    .data_in(top_data),
    .valid_in(top_valid),
    .ready_out(top_ready)
  );
endmodule

module sub_module (
  input clk,
  output reg [7:0] data_out,
  output reg valid_out,
  input ready_in
);
  reg [3:0] count = 0;
  always @(posedge clk) begin
    count <= count + 1;
    data_out <= count;
    valid_out <= count[0];
  end
endmodule

module consumer (
  input clk,
  input [7:0] data_in,
  input valid_in,
  output reg ready_out
);
  always @(posedge clk) begin
    ready_out <= ~ready_out;
  end
endmodule
