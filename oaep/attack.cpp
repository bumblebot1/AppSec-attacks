#include "attack.hpp"

#include  <cstdlib>
#include  <signal.h>
#include  <unistd.h>
#include   <fcntl.h>

using namespace std;

pid_t pid = 0;    // process ID (of either parent or child) from fork

int target_raw[2];   // unbuffered communication: attacker -> attack target
int attack_raw[2];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

void cleanup(int s);

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
  Attack attackInstance(input, target_in, target_out, cleanup);
  attackInstance.Execute();

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