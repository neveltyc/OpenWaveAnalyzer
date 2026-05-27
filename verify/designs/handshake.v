module handshake;
  reg clk = 0;
  reg rst_n = 0;
  reg valid = 0;
  reg ready = 0;
  reg [15:0] data = 0;
  reg [1:0] phase = 0;

  always #5 clk = ~clk;

  initial begin
    $dumpfile("handshake.vcd");
    $dumpvars(0, handshake);
    #2 rst_n = 1;
    #150 $finish;
  end

  // Producer: valid/data
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      valid <= 0;
      data <= 0;
      phase <= 0;
    end else begin
      phase <= phase + 1;
      case (phase)
        0: begin valid <= 1; data <= 16'hAA55; end
        1: begin valid <= 1; data <= 16'h55AA; end
        2: begin valid <= 0; data <= 16'h0000; end
        3: begin valid <= 1; data <= 16'hFFFF; end
      endcase
    end
  end

  // Consumer: ready
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      ready <= 0;
    end else begin
      ready <= ~ready;
    end
  end
endmodule
