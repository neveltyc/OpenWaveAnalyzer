"""Generate Verilog testbench designs for regression testing."""

import os

DESIGNS_DIR = os.path.dirname(os.path.abspath(__file__)) + '/designs'
os.makedirs(DESIGNS_DIR, exist_ok=True)


def write_design(name, content):
    path = os.path.join(DESIGNS_DIR, name)
    with open(path, 'w') as f:
        f.write(content)
    print(f'  Created {name}')


# ===================================================================
# Design 1: Simple counter with mixed signal types
# ===================================================================
write_design('simple_counter.v', '''\
module simple_counter;
  reg clk = 0;
  reg rst_n = 0;
  reg [7:0] counter = 0;
  reg [3:0] state = 0;
  reg flag = 0;

  always #5 clk = ~clk;

  initial begin
    $dumpfile("simple.fst");
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
''')


# ===================================================================
# Design 2: Handshake protocol with valid/ready/data pattern
# ===================================================================
write_design('handshake.v', '''\
module handshake;
  reg clk = 0;
  reg rst_n = 0;
  reg valid = 0;
  reg ready = 0;
  reg [15:0] data = 0;
  reg [1:0] phase = 0;

  always #5 clk = ~clk;

  initial begin
    $dumpfile("handshake.fst");
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
''')


# ===================================================================
# Design 3: Wide bus with x and z values
# ===================================================================
write_design('wide_bus.v', '''\
module wide_bus;
  reg clk = 0;
  reg rst_n = 0;
  reg [31:0] wide_data = 32'hzzzzzzzz;
  reg [63:0] big_bus = 64'hxxxxxxxxxxxxxxxx;
  reg [15:0] addr = 16'hzzzz;
  reg [7:0] byte_en = 8'h00;
  reg [2:0] opcode = 3'bxxx;

  always #5 clk = ~clk;

  initial begin
    $dumpfile("wide_bus.fst");
    $dumpvars(0, wide_bus);
    #2 rst_n = 1;
    #10 wide_data = 32'hDEADBEEF;
    #10 wide_data = 32'hCAFEBABE;
    #10 wide_data = 32'h00000000;
    #10 big_bus = 64'h0123456789ABCDEF;
    #10 addr = 16'h8000;
    #10 byte_en = 8'hFF;
    #10 opcode = 3'b101;
    #10 byte_en = 8'h0F;
    #10 opcode = 3'b010;
    #20 $finish;
  end

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      wide_data <= 32'hzzzzzzzz;
      big_bus <= 64'hxxxxxxxxxxxxxxxx;
      addr <= 16'hzzzz;
      byte_en <= 8'h00;
      opcode <= 3'bxxx;
    end
  end
endmodule
''')


# ===================================================================
# Design 4: Nested hierarchy with scopes
# ===================================================================
write_design('nested_hierarchy.v', '''\
module top;
  reg clk = 0;
  always #5 clk = ~clk;

  initial begin
    $dumpfile("nested.fst");
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
''')


# ===================================================================
# Design 5: Event-type signals (VCD event)
# ===================================================================
write_design('events.v', '''\
module events;
  reg clk = 0;
  event trigger_a, trigger_b, trigger_c;
  reg [7:0] count = 0;

  always #5 clk = ~clk;

  initial begin
    $dumpfile("events.fst");
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
''')


# ===================================================================
# Design 6: Edge cases - single-bit toggles, constant signals
# ===================================================================
write_design('edge_cases.v', '''\
module edge_cases;
  reg clk = 0;
  reg rst_n = 0;
  reg toggle_1 = 0;
  reg toggle_fast = 0;
  reg [0:0] one_bit_bus = 0;
  reg [2:0] three_bit = 3'b000;
  reg static_high = 1;
  reg static_low = 0;

  always #5 clk = ~clk;
  always #10 toggle_fast = ~toggle_fast;

  initial begin
    $dumpfile("edge_cases.fst");
    $dumpvars(0, edge_cases);
    #2 rst_n = 1;
    #10 toggle_1 = 1;
    #20 toggle_1 = 0;
    #10 toggle_1 = 1;
    #5 toggle_1 = 0;
    #15 three_bit = 3'b101;
    #10 three_bit = 3'b010;
    #10 one_bit_bus = 1;
    #10 one_bit_bus = 0;
    #10 three_bit = 3'b111;
    #20 $finish;
  end
endmodule
''')

print('All designs generated.')
