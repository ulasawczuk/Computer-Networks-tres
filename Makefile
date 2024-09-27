all: scanner puzzlesolver

scanner: portScanner.cpp
	g++ -std=c++11 portScanner.cpp -o $@

puzzlesolver: puzzleSolver.cpp
	g++ -std=c++11 puzzleSolver.cpp -o $@

clean:
	rm -f scanner puzzlesolver
