SRCS=$(shell find src/*.cpp)
EXES=$(patsubst src/%.cpp,exe/%.exe,$(SRCS))

all:		$(EXES)
$(EXES):	exe/%.exe:	src/%.cpp
		g++ -I. $^ -o $@
		
