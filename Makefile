CXXFLAGS =-std=c++11 -Wall -ggdb3 -Wextra
LDFLAGS=-lpcap

pcapsession: pcapsession.cc
	$(CXX) $(CXXFLAGS) pcapsession.cc  $(LDFLAGS)  -o pcapsession
