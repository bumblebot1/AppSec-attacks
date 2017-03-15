#include <iostream>
#include <cstring>
#include <gmpxx.h>
#include <fstream>
#include <cstdlib>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

pid_t pid = 0;    // process ID (of either parent or child) from fork

int target_raw[2];   // unbuffered communication: attacker -> attack target
int attack_raw[2];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

void cleanup(int s);

long interact(mpz_class c, mpz_class N, mpz_class d, mpz_class &m)
{
	gmp_fprintf(target_in, "%0256ZX\n%0256ZX\n%0256ZX\n", c.get_mpz_t(), N.get_mpz_t(), d.get_mpz_t());
	fflush(target_in);
    
	int time;
	gmp_fscanf(target_out, "%ld\n%ZX", &time, m.get_mpz_t());
  return time;
}

void test(ifstream& input)
{
  mpz_class N, e;
  string line;
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", N);
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", e);

  mpz_class c = 0b101010101010100101010, m, d=0b1010;
  cout<<c<<endl;
  long time0 = interact(c, N, d, m);
  cout<<"Time for d=1010: "<<time0<<endl;
  d = 0b01001;
  long time1 = interact(c, N, d, m);
  cout<<"Time for d=1001: "<<time1<<endl;
  d = 0b01100;
  long time2 = interact(c, N, d, m);
  cout<<"Time for d=1100: "<<time2<<endl;
  d = 0b01000;
  long time3 = interact(c, N, d, m);
  cout<<"Time for d=1000: "<<time3<<endl;
  cout<<"Diff between 2 bits set and 1 is:"<<time2-time3<<endl;
  d = 0b0100;
  long time4 = interact(c, N, d, m);
  cout<<"Time for d=100: "<<time4<<endl;
  cout<<"Diff for one fewer bits is:"<<time3-time4<<endl;
  d = 0b010;
  long time5 = interact(c, N, d, m);
  cout<<"Time for d=10: "<<time5<<endl;
  cout<<"Diff for two fewer bits is:"<<time3-time5<<endl;
}

int main(int argc, char* argv[]) {
  // Ensure we clean-up correctly if Control-C (or similar) is signalled.
  signal(SIGINT, &cleanup);

  // Create pipes to/from attack target; if it fails the reason is stored
  // in errno, but we'll just abort.
  if(pipe(target_raw) == -1)
  abort();

  if(pipe(attack_raw) == -1)
  abort();

  switch(pid = fork()) { 
    case -1: {
      // The fork failed; reason is stored in errno, but we'll just abort.
      abort();
    }

    case +0: {
      // (Re)connect standard input and output to pipes.
      close(STDOUT_FILENO);
      if(dup2(attack_raw[1], STDOUT_FILENO) == -1)
        abort();

      close(STDIN_FILENO);
      if(dup2(target_raw[0], STDIN_FILENO) == -1)
        abort();
      // Produce a sub-process representing the attack target.
      execl(argv[1], argv[0], NULL);
      // Break and clean-up once finished.
      break;
    }

    default: {
      // Construct handles to attack target standard input and output.
      if((target_out = fdopen(attack_raw[0], "r")) == NULL) 
        abort();

      if((target_in = fdopen(target_raw[1], "w")) == NULL)
        abort();

      break;
    }
  }
  ifstream input(argv[2], ifstream::in);
  test(input);

  cleanup(SIGINT);
}

void cleanup(int s) {
  // Close the   buffered communication handles.
  fclose(target_in);
  fclose(target_out);

  // Close the unbuffered communication handles.
  close(target_raw[0]); 
  close(target_raw[1]); 
  close(attack_raw[0]); 
  close(attack_raw[1]); 

  // Forcibly terminate the attack target process.
  if( pid > 0 )
  kill(pid, SIGKILL);

  // Forcibly terminate the attacker process.
  exit(1); 
}
