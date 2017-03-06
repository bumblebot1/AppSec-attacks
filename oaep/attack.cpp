#include "attack.hpp"

using namespace std;

Attack::Attack(ifstream& input) {
  string line;
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", N);
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", e);
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", label);
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", c);
  interactionCount = 0;
}

void Attack::printAll() {
  gmp_printf("%ZX\n\n%ZX\n\n%ZX\n\n%ZX\n\n", N, e, label, c);
}

int main(int argc, char* argv[]){
  ifstream input(argv[2], ifstream::in);
  Attack instance(input);
  instance.printAll();
}