/* Dump GNU binutils opcode tables as text for the test corpora:
     dumpopc alpha     alpha_opcodes[]: name opcode mask flags operand-indices...
     dumpopc s390      s390_opcodes[]:  name opcode mask length modes min_cpu flags operands...
     dumpopc operands  s390_operands[]: index bits shift flags
   Build: build-dumpopc.sh */
#include <stdio.h>
#include "opcode/alpha.h"
#include "opcode/s390.h"
int main(int argc,char**argv){
  if(argv[1][0]=='a'){
    for(unsigned i=0;i<alpha_num_opcodes;i++){const struct alpha_opcode*o=&alpha_opcodes[i];
      printf("%s %08x %08x %x",o->name,o->opcode,o->mask,o->flags);
      for(int j=0;o->operands[j];j++)printf(" %d",o->operands[j]); printf("\n");}
  } else if(argv[1][0]=='o'){
    int max=0;
    for(int i=0;i<s390_num_opcodes;i++)for(int j=0;s390_opcodes[i].operands[j];j++)if(s390_opcodes[i].operands[j]>max)max=s390_opcodes[i].operands[j];
    for(int i=0;i<=max;i++)printf("%d %d %d %lx\n",i,s390_operands[i].bits,s390_operands[i].shift,s390_operands[i].flags);
  } else {
    for(int i=0;i<s390_num_opcodes;i++){const struct s390_opcode*o=&s390_opcodes[i];
      printf("%s ",o->name); for(int j=0;j<6;j++)printf("%02x",o->opcode[j]); printf(" ");
      for(int j=0;j<6;j++)printf("%02x",o->mask[j]);
      printf(" %d %x %x %x",o->oplen,o->modes,o->min_cpu,o->flags);
      for(int j=0;o->operands[j];j++)printf(" %d",o->operands[j]); printf("\n");}
  }
}
