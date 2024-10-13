#include <stdio.h>
#include <unistd.h>
void init(){
    fclose(stderr);
    setvbuf(stdin,  0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}
int main(){
    init();
    char buf[0x100]; 
    puts("Si vous réussissez à maîtriser le Totem, le chemin du guerrier s'ouvrira un peu plus devant vous. Mais ce n'est que le début. D'autres épreuves plus difficiles vous attendent, où chaque pas vous rapprochera un peu plus du secret ultime du guerrier légendaire.\n\nQu'avez-vous à me dire ?");
    read(0, buf, 0x100);
    void (* p )(); 
    p = (void (*)()) buf;
    p();
    return 0;
}
