module bitcoin_hash (
  input  logic        clk, reset_n, start,
  input  logic [15:0] message_addr, output_addr,
  output logic        done, mem_clk, mem_we,
  output logic [15:0] mem_addr,
  output logic [31:0] mem_write_data,
  input  logic [31:0] mem_read_data
);

parameter int NUM_NONCES = 16;

assign mem_clk = clk;

parameter int k[64] = '{
  32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
  32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
  32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
  32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
  32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
  32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
  32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
  32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

localparam logic [31:0] H0C=32'h6a09e667, H1C=32'hbb67ae85, H2C=32'h3c6ef372, H3C=32'ha54ff53a,
                        H4C=32'h510e527f, H5C=32'h9b05688c, H6C=32'h1f83d9ab, H7C=32'h5be0cd19;

function automatic logic [31:0] ror(input logic [31:0] x, input logic [7:0] r);
  ror = (x >> r) | (x << (32-r));
endfunction

function automatic logic [255:0] sha256_op(
  input logic [31:0] a,b,c,d,e,f,g,h,
  input logic [31:0] w, kk
);
  logic [31:0] S1, S0, ch, maj, t1, t2;
  S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
  ch = (e & f) ^ ((~e) & g);
  t1 = h + S1 + ch + kk + w;
  S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
  maj = (a & b) ^ (a & c) ^ (b & c);
  t2 = S0 + maj;
  sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
  
endfunction

function automatic logic [31:0] wt_next(
  input logic [31:0] w0,  
  input logic [31:0] w1,
  input logic [31:0] w9,  
  input logic [31:0] w14 
);

  logic [31:0] s0, s1;
  s0 = ror(w1,7)  ^ ror(w1,18) ^ (w1 >> 3);
  s1 = ror(w14,17)^ ror(w14,19)^ (w14 >> 10);
  wt_next = w0 + s0 + w9 + s1;
  
endfunction

typedef enum logic [3:0] {
  S_IDLE, S_READ,
  S_P1_LOAD, S_P1_RUN,
  S_P2_LOAD, S_P2_RUN,
  S_P3_LOAD, S_P3_RUN,
  S_WSET, S_WCOMMIT
} state_t;

state_t state;

logic cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_wdata;
logic [15:0] offset;

assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_wdata;

logic [31:0] header[0:18];
logic [31:0] wwin[0:15];

logic [31:0] a,b,c,d,e,f,g,h;
logic [31:0] h0,h1,h2,h3,h4,h5,h6,h7;
logic [31:0] p1_0,p1_1,p1_2,p1_3,p1_4,p1_5,p1_6,p1_7;

logic [6:0]  t;
logic [4:0]  nonce;

assign done = (state == S_IDLE);

always_ff @(posedge clk, negedge reset_n) 
	begin
	  if (!reset_n) begin
		 state <= S_IDLE;
		 cur_we <= 1'b0;
		 cur_addr <= '0;
		 cur_wdata <= '0;
		 offset <= '0;
		 nonce <= '0;
		 t <= '0;
		 a<=0; b<=0; c<=0; d<=0; e<=0; f<=0; g<=0; h<=0;
		 h0<=0; h1<=0; h2<=0; h3<=0; h4<=0; h5<=0; h6<=0; h7<=0;
		 p1_0<=0; p1_1<=0; p1_2<=0; p1_3<=0; p1_4<=0; p1_5<=0; p1_6<=0; p1_7<=0;
	  end else begin
		 unique case (state)
			S_IDLE: begin
			  cur_we <= 1'b0;
			  if (start) begin
				 cur_addr <= message_addr;
				 offset <= 16'd0;
				 nonce <= 5'd0;
				 state <= S_READ;
			  end
			end

			S_READ: begin
			  cur_we <= 1'b0;
			  if (offset <= 16'd19) 
			  begin
					 if (offset != 0) header[offset-1] <= mem_read_data;
					 offset <= offset + 16'd1;
			  end else 
			  begin
					 offset <= 16'd0;
					 h0<=H0C; h1<=H1C; h2<=H2C; h3<=H3C; h4<=H4C; h5<=H5C; h6<=H6C; h7<=H7C;
					 a<=H0C; b<=H1C; c<=H2C; d<=H3C; e<=H4C; f<=H5C; g<=H6C; h<=H7C;
					 state <= S_P1_LOAD;
			  end
      end

      S_P1_LOAD: 
		begin
			  for (int i=0;i<16;i++) wwin[i] <= header[i];
			  t <= 7'd0;
			  state <= S_P1_RUN;
      end

      S_P1_RUN: 
		begin
			  logic [31:0] wt;
			  logic [31:0] na,nb,nc,nd,ne,nf,ng,nh;
			  if (t < 7'd16) wt = wwin[t];
			  else begin
				 wt = wt_next(wwin[0], wwin[1], wwin[9], wwin[14]);
				 for (int i=0;i<15;i++) wwin[i] <= wwin[i+1];
				 wwin[15] <= wt;
        end
		  
        {na,nb,nc,nd,ne,nf,ng,nh} = sha256_op(a,b,c,d,e,f,g,h, wt, k[t]);

        if (t == 7'd63) 
		  begin
				 h0 <= h0 + na; h1 <= h1 + nb; h2 <= h2 + nc; h3 <= h3 + nd;
				 h4 <= h4 + ne; h5 <= h5 + nf; h6 <= h6 + ng; h7 <= h7 + nh;
				 p1_0 <= h0 + na; p1_1 <= h1 + nb; p1_2 <= h2 + nc; p1_3 <= h3 + nd;
				 p1_4 <= h4 + ne; p1_5 <= h5 + nf; p1_6 <= h6 + ng; p1_7 <= h7 + nh;
				 state <= S_P2_LOAD;
        end else 
		  begin
				 a<=na; b<=nb; c<=nc; d<=nd; e<=ne; f<=nf; g<=ng; h<=nh;
				 t <= t + 7'd1;
        end
      end

      S_P2_LOAD: begin
        wwin[0] <= header[16];
        wwin[1] <= header[17];
        wwin[2] <= header[18];
        wwin[3] <= {27'd0, nonce};
        wwin[4] <= 32'h80000000;
        for (int i=5;i<15;i++) wwin[i] <= 32'h00000000;
        wwin[15] <= 32'd640;

        h0<=p1_0; h1<=p1_1; h2<=p1_2; h3<=p1_3; h4<=p1_4; h5<=p1_5; h6<=p1_6; h7<=p1_7;
        a <=p1_0; b <=p1_1; c <=p1_2; d <=p1_3; e <=p1_4; f <=p1_5; g <=p1_6; h <=p1_7;
        t <= 7'd0;
        state <= S_P2_RUN;
      end

      S_P2_RUN: 
		begin
				  logic [31:0] wt;
				  logic [31:0] na,nb,nc,nd,ne,nf,ng,nh;
				  if (t < 7'd16) wt = wwin[t];
				  else begin
						 wt = wt_next(wwin[0], wwin[1], wwin[9], wwin[14]);
						 for (int i=0;i<15;i++) wwin[i] <= wwin[i+1];
						 wwin[15] <= wt;
				  end
				  {na,nb,nc,nd,ne,nf,ng,nh} = sha256_op(a,b,c,d,e,f,g,h, wt, k[t]);

				  if (t == 7'd63) 
				  begin
						 h0 <= h0 + na; h1 <= h1 + nb; h2 <= h2 + nc; h3 <= h3 + nd;
						 h4 <= h4 + ne; h5 <= h5 + nf; h6 <= h6 + ng; h7 <= h7 + nh;
						 state <= S_P3_LOAD;
				  end else 
				  begin
						 a<=na; b<=nb; c<=nc; d<=nd; e<=ne; f<=nf; g<=ng; h<=nh;
						 t <= t + 7'd1;
				  end
				end

		
				S_P3_LOAD: 
				begin
					  wwin[0]<=h0; wwin[1]<=h1; wwin[2]<=h2; wwin[3]<=h3;
					  wwin[4]<=h4; wwin[5]<=h5; wwin[6]<=h6; wwin[7]<=h7;
					  wwin[8]<=32'h80000000;
					  for (int i=9;i<15;i++) wwin[i] <= 32'h00000000;
					  wwin[15] <= 32'd256;

					  h0<=H0C; h1<=H1C; h2<=H2C; h3<=H3C; h4<=H4C; h5<=H5C; h6<=H6C; h7<=H7C;
					  a <=H0C; b <=H1C; c <=H2C; d <=H3C; e <=H4C; f <=H5C; g <=H6C; h <=H7C;
					  t <= 7'd0;
					  state <= S_P3_RUN;
				end

				S_P3_RUN: 
				begin
				  logic [31:0] wt;
				  logic [31:0] na,nb,nc,nd,ne,nf,ng,nh;
				  if (t < 7'd16) wt = wwin[t];
				  else 
				  begin
						 wt = wt_next(wwin[0], wwin[1], wwin[9], wwin[14]);
						 for (int i=0;i<15;i++) wwin[i] <= wwin[i+1];
						 wwin[15] <= wt;
				  end
				  {na,nb,nc,nd,ne,nf,ng,nh} = sha256_op(a,b,c,d,e,f,g,h, wt, k[t]);

				  if (t == 7'd63) 
				  begin
						 cur_we   <= 1'b0;
						 cur_addr <= output_addr;
						 offset   <= nonce;
						 cur_wdata<= H0C + na;
						 state    <= S_WSET;
				  end else 
				  begin
						 a<=na; b<=nb; c<=nc; d<=nd; e<=ne; f<=nf; g<=ng; h<=nh;
						 t <= t + 7'd1;
				  end
      end

 
      S_WSET: 
		begin
			  cur_we <= 1'b1;
			  state  <= S_WCOMMIT;
      end

      S_WCOMMIT: 
		begin
			  cur_we <= 1'b0;
			  if (nonce + 5'd1 < NUM_NONCES) 
			  begin
				 nonce <= nonce + 5'd1;
				 state <= S_P2_LOAD;
			  end else 
			  begin
				 state <= S_IDLE;
			  end
      end

      default: state <= S_IDLE;
    endcase
  end
end

endmodule

