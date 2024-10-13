#include <stdio.h>
#include <stdlib.h>

void init(){
  fclose(stderr);
  setvbuf(stdin,  0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  init();
  puts("L'esprit attend...\n\nQuel geste souhaitez-vous faire ?");
  system("/bin/sh");
  return EXIT_SUCCESS;
}
