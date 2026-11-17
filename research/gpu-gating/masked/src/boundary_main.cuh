// RFC-0014 §5: binary framing contains inputs and output length, never expected values.
int main() {
  u32 h[6];
  while (true) {
    auto read=std::fread(h,4,6,stdin);
    if (!read) return std::ferror(stdin)?1:0;
    if (read!=6) return 2;
    std::vector<u32> in(h[4]),out(h[5],0xdeadbeef);
    if (std::fread(in.data(),4,in.size(),stdin)!=in.size()) return 3;
    u64 a=h[1],b=h[2],c=h[3];
    // Copy kernels before source.cu use the actual grid-stride macro with one worker.
    blockIdx.x=threadIdx.x=0;blockDim.x=gridDim.x=1;
    switch(h[0]) {
      case 0: mask_kernel(out.data(),in.data()+b,in.data(),b,a,1ULL<<a);break;
      case 1: tile_kernel(out.data(),in.data(),a-1,2*a);break;
      case 2: std::copy(in.begin(),in.end(),out.begin());dup_kernel(out.data(),a);break;
      case 3:
        blockDim.x=32;blockDim.y=8;
        for(blockIdx.y=0;blockIdx.y<(a+31)/32;blockIdx.y++)
          for(blockIdx.x=0;blockIdx.x<(b+31)/32;blockIdx.x++)
            for(host_phase=0;host_phase<2;host_phase++)
              for(threadIdx.y=0;threadIdx.y<8;threadIdx.y++)
                for(threadIdx.x=0;threadIdx.x<32;threadIdx.x++)
                  transpose_kernel(in.data(),out.data(),a,b);
        break;
      case 4: out=in;bitrev_kernel(out.data(),a,b);break;
      case 5: case 6:
        std::copy(in.begin(),in.begin()+a*b,out.begin());
        level_kernel(out.data(),in.data()+a*b,c,a,b,h[0]==6);break;
      case 7: out=in;scale_kernel(out.data(),b,a);break;
      case 8: case 9: {
        unsigned char prefix[43];for(int i=0;i<43;i++)prefix[i]=in[i];
        if(h[0]==8)leaf_kernel(in.data()+68,a,b,prefix,in.data()+43,in.data()+51,in[67],out.data());
        else node_kernel(in.data()+43,out.data(),a,b,prefix);
        break;
      }
      case 10: eq_kernel(out.data(),in.data()+4,a,in[0],in[1],in[2],in[3],1ULL<<a);break;
      default:return 4;
    }
    if(std::fwrite(out.data(),4,out.size(),stdout)!=out.size())return 5;
  }
}
