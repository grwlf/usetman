#include <stdio.h>
#include <stdlib.h>
#include <shadow.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <pwd.h>
#include <sys/file.h>
#include <signal.h>
#include <time.h>
#include <ext/stdio_filebuf.h>

#include <sstream>
#include <vector>
#include <functional>
#include <cassert>
#include <list>
#include <iostream>
#include <regex>
#include <climits>
#include <cstdlib>

using namespace std;

static inline std::string mks_(function<void(ostringstream &oss)> f) {
  ostringstream oss;
  f(oss);
  return oss.str();
}

#define ss(x) mks_([&](std::ostringstream &oss){ oss << x ;})

#define derror(cmd, args...) fprintf(stderr, "%s:%d:" cmd "\n", __func__, __LINE__, ##args)
#define dbg(ss) do{ cerr <<  __func__ << ":" <<  __LINE__ << ": " << ss << endl; } while(0)
#define badret_if(cnd) do{ if(cnd){ derror("Error: %s", #cnd); return false; } } while(0)
#define exit_if(cnd) do{ if(cnd){ derror("Error: %s", #cnd); exit(EXIT_FAILURE); } } while(0)
#define throw_(s) do{ int _errno = errno; throw string( ss( __func__ << ":" << __LINE__ << ":e" << _errno << ": " << s)); } while(0)
#define throw_if(cnd) do{ if(cnd){ throw_( #cnd ); } } while(0)
#define throw_if_not(cnd) throw_if(!(cnd))

inline void in_try_catch(std::function<void()> f) {
    try{
      f();
    }
    catch(std::exception &e) {
      derror("exception %s", e.what());
      assert(false);
    }
    catch(...) {
      derror("exception '...'");
      assert(false);
    }
}

struct guard {
  guard() : g(noop){};
  guard(std::function<void()> g_) : g(g_) {};
  guard(guard &&g_) : g(g_.g) { g_.g = noop; };

  void next(function<void()> f) { g = bind(after,g,f); };

  ~guard() { in_try_catch( g ); }

private:
  static void after(std::function<void()> f1, std::function<void()> f2) { f2(); f1(); }
  static void paired(std::function<void()> f1, std::function<void()> f2) { f2(); f1(); }
  static void noop() { }
  std::function<void()> g;
};

struct transaction {
  typedef std::function<void()> thandler;

private:
  bool commited;
  thandler cm;
  thandler cl;

  static void noop() { }

public:

  transaction() : cm(noop), cl(noop), commited(false) {}
  ~transaction() { if(!commited) in_try_catch(cl); }

  void set(thandler cm_, thandler cl_) { cm = cm_; cl = cl_; }

  void commit() { cm(); commited = true; }
};

#define CNC(x, y) x ## y
#define CNC2(x, y) CNC(x, y)
#define guarded(txt) guard CNC2(g , __LINE__) ( txt )
#define atret(c) guarded( [&](){ c ; } )
#define atret_(g,c) g.next( [&](){ c ; } )

#define SCOPECHAR(nam, src) \
  char * nam = strdup(src); \
  throw_if(nam == NULL); \
  atret( free(nam); );

struct args {
  args() : wait_sec(10), force(false) {}

  string eth;
  int wait_sec;
  bool force;
};

bool ip_enabled(const string ip) {
  if(ip == "" || ip == "-")
    return false;
  return true;
}

string spc(string s) {
  return string(" " + s + " ");
}

void ip_check(const string &ip) {
  if(ip == "-")
    return; /* means 'disabled' */
  int a,b,c,d; char e;
  int ret = sscanf(ip.c_str(),"%d.%d.%d.%d%c", a,b,c,d,e);
  throw_if( ret == EOF );
  throw_if( ret != 4 );
}

void sys(string s) {
  int ret = system(s.c_str());
  dbg("\"" << s << "\" ret " << ret);
  throw_if(ret != 0);
}

typedef enum{dryrun,force} cmdmode_t;

void apply_state(istream &fs, const args &a, cmdmode_t mode) {

  guard g;
  FILE *pp = NULL;

  if(mode == force) {

    /* Kill dhcpc (if any) */
    fstream dhcppid(SETMAN_DHCPPID, ios_base::in);
    int pid = 0;
    if(dhcppid >> pid && pid > 0) {
      int ret = kill(pid, SIGUSR2);
      if(ret != 0)
        dbg("failed to send SIGUSR2 to " << pid);
      usleep(500 * 1000); /* 0.5 sec */
      ret = kill(pid, SIGINT);
      if(ret != 0)
        dbg("Failed to send SIGINT to " << pid);
    }
    else {
      dbg("Error accessing " << SETMAN_DHCPPID << " (file doesn't exist?)");
    }

    /* Reset the interface */
    sys( ss(SETMAN_IFCONFIG << spc(a.eth) << " down" ) );

    /* Reset the iptables */
    sys(SETMAN_IPTABLES " -P INPUT DROP");
    sys(SETMAN_IPTABLES " -P OUTPUT ACCEPT");
    sys(SETMAN_IPTABLES " -P FORWARD DROP");

    sys(SETMAN_IPTABLES " -F");
    sys(SETMAN_IPTABLES " -X");

    sys(SETMAN_IPTABLES " -A INPUT -i lo -j ACCEPT");
    sys(SETMAN_IPTABLES " -A INPUT -p ICMP -j ACCEPT");
    sys(SETMAN_IPTABLES " -A INPUT -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT");

    /* Launching the upwd*/
    pp = popen(SETMAN_UPWD, "we");
    throw_if(pp == NULL);
    atret_(g, if(pp) pclose(pp); );
  }

  string line;
  while(getline(fs, line)) {

    dbg("Command" << (mode == dryrun ? " (dryrun): " : ": ") << line );

    string cmd;
    istringstream s(line);

    throw_if_not( s >> cmd );

    if(cmd == "dhcp") {

      if(mode == dryrun)
        continue;

      sys( SETMAN_DHCP );
    }
    else if( cmd == "ip" ) {
      string ip, mask, gw, dns1, dns2, dns3, e;
      s >> ip >> mask >> gw >> dns1 >> dns2 >> dns3;
      throw_if( s >> e );

      ip_check(ip);
      ip_check(mask);
      ip_check(gw);

      if(mode == dryrun)
        continue;

      sys( ss(SETMAN_IFCONFIG << spc(a.eth) << " up ") );

      sys( ss(SETMAN_IFCONFIG << spc(a.eth) << spc(ip) << " netmask " << spc(mask) ));

      if(gw != "-") {
        sys( ss(SETMAN_ROUTE << spc(a.eth) << " add default gw " << spc(gw) ));
      }

      bool moved = false;
      const char *tmp = SETMAN_RESOLVCONF ".new";
      const char *fin = SETMAN_RESOLVCONF;
      FILE* f = fopen(tmp, "we");
      throw_if(f == NULL);
      atret( if(f) fclose(f) );
      atret( if(!moved) remove(tmp) );

      if(ip_enabled(dns1)) {
        fprintf(f, "nameserver %s\n", dns1.c_str());
      }

      if(ip_enabled(dns2)) {
        fprintf(f, "nameserver %s\n", dns2.c_str());
      }

      if(ip_enabled(dns3)) {
        fprintf(f, "nameserver %s\n", dns3.c_str());
      }

      throw_if( 0 != fclose(f) );
      f = NULL;

      throw_if( 0 != rename(tmp, fin) );
      moved = true;
    }
    else if(cmd == "allow") {
      string ip, mask, e;
      s >> ip >> mask;
      throw_if( s >> e );

      if(mode == dryrun)
        continue;

      if(ip_enabled(mask)) {
        sys( ss(SETMAN_IPTABLES << " -A input -s '" << ip << "/" << mask << "' -j ACCEPT"));
      }
      else {
        sys( ss(SETMAN_IPTABLES << " -A input -s '" << ip << "' -j ACCEPT"));
      }
    }
    else if (cmd == "user") {
      string usr, pwd, e;
      s >> usr >> pwd;
      throw_if( s >> e );

      if(mode == dryrun)
        continue;

      fprintf(pp,"%s %s\n", usr.c_str(), pwd.c_str());
    }
    else if (cmd == "serial") {
      string baud, parity, e;

      s >> baud >> parity;
      throw_if( s >> e );

      if(mode == dryrun)
        continue;

      throw_("not implemented");
    }
    else {
      throw_("invalid command '" << cmd << "'");
    }
  }

  if(pp) {
    throw_if( 0 != pclose(pp) );
    pp = NULL;
  }
}

void lockfile(guard &g) {
  int lockfd = open ( SETMAN_LOCKFILE, O_RDONLY | O_NOCTTY | O_NOFOLLOW | O_CREAT | O_CLOEXEC, 0666 );
  throw_if(lockfd < 0);
  g.next( [=]() { close(lockfd); } );
  throw_if( 0 != flock(lockfd, LOCK_EX | LOCK_NB ));
  g.next( [=]() { dbg("Unlocking"); flock(lockfd, LOCK_UN); } );
}

typedef enum { confirmed, rejected } conf_t;

volatile bool sigint = false;
volatile bool sigusr1 = false;

conf_t confirm(const args &a) {

  fstream pidf(SETMAN_PIDFILE, ios_base::out);
  atret( remove(SETMAN_PIDFILE); );
  
  pidf << getpid();
  pidf.close();
  throw_if( pidf.fail() );

  {
    struct sigaction s;
    memset(&s, 0, sizeof(struct sigaction));
    s.sa_handler = [](int signo) -> void { sigusr1 = true; };
    sigemptyset(&s.sa_mask);
    s.sa_flags = 0;
    throw_if( 0 != sigaction(SIGUSR1, &s, NULL));
  }

  cout << SETMAN_PIDFILE << endl;

  int s;
  for(s=0; s<a.wait_sec && !sigint && !sigusr1 ; s++) {
    int ret = sleep(1);
    if(ret != 0) {
      dbg("Interruped: ret " << ret);
      break;
    }
  }

  if(sigusr1)
    return confirmed;
  else {
    if(s == a.wait_sec) {
      dbg("Timeout");
    }
    return rejected;
  }
}

int main(int argc, char **argv) {

  int exitcode = 2;

  try {

    args a;

    struct sigaction s;
    memset(&s, 0, sizeof(struct sigaction));
    s.sa_handler = [](int signo) -> void { sigint = true; };
    sigemptyset(&s.sa_mask);
    s.sa_flags = 0;
    throw_if( 0 != sigaction(SIGHUP, &s, NULL));
    throw_if( 0 != sigaction(SIGINT, &s, NULL));
    throw_if( 0 != sigaction(SIGPIPE, &s, NULL));

    guard g;
    char tmpnm[] = SETMAN_TMP "/setman.XXXXXX";
    bool tmpdead = true;

    string fname;

    for(int i=1; i< argc; i++) {
      if(string(argv[i]) == "-e") {
        throw_if(++i >= argc);
        a.eth = string(argv[i]);
      }
      if(string(argv[i]) == "-w") {
        throw_if(++i >= argc);
        a.wait_sec = stoi(string(argv[i]));
      }
      if(string(argv[i]) == "-f") {
        a.force = true;
      }
      if(string(argv[i]) == "-") {
        int tmpfd = mkstemp(tmpnm);
        throw_if( tmpfd < 0 );
        tmpdead = false;
        atret_(g, if(!tmpdead) { dbg("Removing " << tmpnm); remove(tmpnm) ;} );
        atret( if(tmpfd>0) { dbg("Closing " << tmpnm); close(tmpfd); } );

        __gnu_cxx::stdio_filebuf<char> filebuf(tmpfd, std::ios::out);
        ostream tmps(&filebuf);
        tmpfd = -1;

        string line;
        while(getline(cin, line)) {
          throw_if_not( tmps << line << endl );
        }
        fname = tmpnm;
      }
      else {
        fname = string(argv[i]);
      }
    }

    dbg("Fname " << fname);

    throw_if( a.eth.length() == 0 );


    lockfile(g);

    {
      dbg("Syntax " << fname);
      fstream fs(fname, ios_base::in);
      apply_state(fs, a, dryrun);

      dbg("Syntax " << SETMAN_STATE);
      fstream f(SETMAN_STATE, ios_base::in);
      apply_state(f, a, dryrun);
    }

    bool restore = true;

    try {

      fstream fs(fname, ios_base::in);
      apply_state(fs, a, force);

      if(a.force) {

        dbg("Forcing");
        throw_if( 0 != rename(fname.c_str(), SETMAN_STATE) );
        tmpdead = true;
        restore = false;

      }
      else {

        conf_t c = confirm(a);

        switch(c) {

          case confirmed:
            dbg("Confirming");
            throw_if( 0 != rename(fname.c_str(), SETMAN_STATE) );
            tmpdead = true;
            restore = false;
            break;

          default:
            dbg("Discarding");
            break;
        }
      }
    }
    catch(string &e) {
      cerr << e << " (will rollback)" << endl;
    }
    catch(exception &e) {
      cerr << e.what() << " (will rollback)" << endl;
    }

    if(restore) {
      dbg("Rolling back");
      fstream f(SETMAN_STATE, ios_base::in);
      apply_state(f, a, force);

      exitcode = 1;
    }
    else {

      exitcode = 0;
    }
  }
  catch(string &e) {
    cerr << e << endl;
  }
  catch(exception &e) {
    cerr << e.what() << endl;
  }
  catch(...) {
    cerr << "unknown" << endl;
  }

  return exitcode;
}

