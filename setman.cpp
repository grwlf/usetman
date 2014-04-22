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

static string g_dmode = "?";

static inline std::string mks_(function<void(ostringstream &oss)> f) {
  ostringstream oss;
  f(oss);
  return oss.str();
}

#define ss(x) mks_([&](std::ostringstream &oss){ oss << x ;})

#define dbg(ss) do{ cerr <<  "setman[" << g_dmode << "]: " << __func__ << ":" <<  __LINE__ << ": " << ss << endl; } while(0)
#define throw_(s) do{ int _errno = errno; throw string( ss( __func__ << ":" << __LINE__ << ":e" << _errno << ": " << s)); } while(0)
#define throw_if(cnd) do{ if(cnd){ throw_( #cnd ); } } while(0)
#define throw_if_not(cnd) throw_if(!(cnd))

inline void in_try_catch(std::function<void()> f) {
    try{
      f();
    }
    catch(std::exception &e) {
      dbg("exception " << e.what());
      assert(false);
    }
    catch(...) {
      dbg("exception '...'");
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

#define DEFAULT_WAIT 10

struct args {
  args() : wait_sec(DEFAULT_WAIT), force(false) {}

  string eth;
  int wait_sec;
  bool force;
};

bool ip_enabled(const string ip) {
  if(ip == "" || ip == "-")
    return false;
  return true;
}

string spc(const string &s) {
  return string(" " + s + " ");
}

void ip_check(const string &ip) {
  if(ip == "-")
    return; /* means 'disabled' */
  int a=0,b=0,c=0,d=0;
  char buf[256];
  sscanf(ip.c_str(),"%d.%d.%d.%d", &a,&b,&c,&d);
  snprintf(buf, 256, "%d.%d.%d.%d", a,b,c,d);
  throw_if( ip != buf );
}

void sys(string s) {
  int ret = system(s.c_str());
  dbg("\"" << s << "\" ret " << ret);
  throw_if(ret != 0);
}

typedef enum{dryrun,force} cmdmode_t;
typedef function<bool(string,istream&)> fchecker_t;

void with_ip(cmdmode_t mode, const args &a, function< void( fchecker_t ) > f) {

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
  }

  f([&](string cmd, istream &s) {

    if(cmd == "dhcp") {

      if(mode == dryrun)
        return true;

      sys( SETMAN_DHCP );
    }
    else if( cmd == "ip" ) {
      string ip, mask, gw, dns1, dns2, dns3, e;
      s >> ip >> mask >> gw >> dns1 >> dns2 >> dns3;
      throw_if( s >> e );

      ip_check(ip);
      ip_check(mask);
      ip_check(gw);

      if(mode == force) {

        sys( ss(SETMAN_IFCONFIG << spc(a.eth) << " up ") );

        sys( ss(SETMAN_IFCONFIG << spc(a.eth) << spc(ip) << " netmask " << spc(mask) ));

        if(gw != "-") {
          sys( ss(SETMAN_ROUTE << " add default gateway " << spc(gw) ));
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
    }
    else if(cmd == "off") {
      string e;
      throw_if( s >> e );
      /* no args, do nothing */
    }
    else if(cmd == "allow") {
      string ip, mask, e;
      s >> ip >> mask;
      throw_if( s >> e );

      if(mode == force) {
        if(ip_enabled(mask)) {
          sys( ss(SETMAN_IPTABLES << " -A input -s '" << ip << "/" << mask << "' -j ACCEPT"));
        }
        else {
          sys( ss(SETMAN_IPTABLES << " -A input -s '" << ip << "' -j ACCEPT"));
        }
      }
    }
    else {
      return false;
    }

    return true;
  });
}

void with_user(cmdmode_t mode, function< void( fchecker_t ) > f) {

  FILE *pp = NULL;

  if(mode == force) {
    pp = popen(SETMAN_UPWD, "we");
    throw_if(pp == NULL);
  }

  f([&](string cmd, istream &s) {

    if (cmd == "user") {
      string usr, pwd, e;
      s >> usr >> pwd;
      throw_if( s >> e );

      if(pp)
        fprintf(pp,"%s %s\n", usr.c_str(), pwd.c_str());

      return true;
    }

    return false;

  });

  if(pp) pclose(pp);
}

void with_serial(cmdmode_t mode, function< void( fchecker_t ) > f) {

  if(mode == force) {
  }

  f([&](string cmd, istream &s) {
    if (cmd == "serial") {
      string baud, parity, stop, data, flow, e;

      s >> baud >> parity >> stop >> data >> flow;
      throw_if( s >> e );

      if(mode == force) {

        throw_("Not implemented. args: serial "
          << spc(baud) << spc(parity) << spc(stop) << spc(data) << spc(flow) << e);

      }

    }
    else {
      return false;
    }

    return true;
  });
}


typedef function<void(istream&, const args&, cmdmode_t)> fapplier_t;

void apply_state_all(istream &fs, const args &a, cmdmode_t mode) {

  with_ip(mode, a, [&](fchecker_t ip_chk) {

  with_user(mode, [&](fchecker_t user_chk) {

  with_serial(mode, [&](fchecker_t serial_chk) {

    string line;
    while(getline(fs, line)) {

      dbg("Command" << (mode == dryrun ? " (dryrun): " : ": ") << line );

      string cmd;
      istringstream s(line);

      throw_if_not( s >> cmd );

      if(ip_chk(cmd, s))
        continue;
      if(user_chk(cmd, s))
        continue;
      if(serial_chk(cmd, s))
        continue;
      else  {
        throw_("Invalid command '" << cmd << "'");
      }
    }

  });

  });

  });
}

void apply_state_net(istream &fs, const args &a, cmdmode_t mode) {

  with_ip(mode, a, [&](fchecker_t ip_chk) {

    string line;
    while(getline(fs, line)) {

      dbg("Command" << (mode == dryrun ? " (dryrun): " : ": ") << line );

      string cmd;
      istringstream s(line);

      throw_if_not( s >> cmd );

      if(ip_chk(cmd, s))
        continue;

      else  {
        throw_("Invalid command '" << cmd << "'");
      }
    }

  });
}

void apply_state_serial(istream &fs, const args &a, cmdmode_t mode) {

  with_serial(mode, [&](fchecker_t serial_chk) {

    string line;
    while(getline(fs, line)) {

      dbg("Command" << (mode == dryrun ? " (dryrun): " : ": ") << line );

      string cmd;
      istringstream s(line);

      throw_if_not( s >> cmd );

      if( serial_chk(cmd, s) )
        continue;
      else {
        throw_("Invalid command '" << cmd << "'");
      }
    }

  });
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

void usage()  {
  cerr << endl;
  cerr << "Usage: setman -e ETH [-w SEC] [-f] [-m mode] (-|FILE)" << endl;
  cerr << "         -e ETH  Network interface" << endl;
  cerr << "         -w SEC  Wait SEC seconds for confirmation" << endl;
  cerr << "                 (Default: " << DEFAULT_WAIT << " secons)" << endl;
  cerr << "         -f      Force applying, don't wait for confirmation" << endl;
  cerr << "         FILE    New command file" << endl;
  cerr << "Signals:" << endl;
  cerr << "         SIGUSR1 Confirm the changes" << endl;
  cerr << "Files:" << endl;
  cerr << "         PID file:   " << SETMAN_PIDFILE << endl;
  cerr << "         State:      " << SETMAN_STATE << "[.mode]" << endl;
  cerr << "         Lock file:  " << SETMAN_LOCKFILE << " (access via flock)" << endl;
  exit(3);
}

int main(int argc, char **argv) {

  int exitcode = 2;
  bool show_usage = true;

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

    string fname;
    string mode;

    for(int i=1; i< argc; i++) {
      if(string(argv[i]) == "-e") {
        throw_if(++i >= argc);
        a.eth = string(argv[i]);
      }
      else if(string(argv[i]) == "-w") {
        throw_if(++i >= argc);
        a.wait_sec = stoi(string(argv[i]));
      }
      else if(string(argv[i]) == "-f") {
        a.force = true;
      }
      else if(string(argv[i]) == "-h" || string(argv[i]) == "--help") {
        usage();
      }
      else if(string(argv[i]) == "-") {
        fname = "-";
      }
      else if(string(argv[i]) == "-m") {
        throw_if(++i >= argc);
        g_dmode = string(argv[i]);
        mode = string(".") + string(argv[i]);
      }
      else {
        fname = string(argv[i]);
      }
    }

    fapplier_t apply_state = apply_state_all;

    if(mode == ".serial") {
      apply_state = apply_state_serial;
    }
    else if (mode == ".net") {
      apply_state = apply_state_net;
    }
    else if (mode == ".all" || mode == "") {
      apply_state = apply_state_all;
      g_dmode = "all";
    }
    else {
      throw_("Invalid mode " << mode);
    }


    guard g;
    string stnm = SETMAN_STATE + mode;
    string tmpnm = stnm + ".new";
    bool tmpdead = true;

    if(a.eth.length() == 0) {
      const char *eth = getenv("ETH");
      throw_if(eth == NULL);
      a.eth = eth;
    }

    throw_if( a.eth.length() == 0 );

    if(fname == "-") {
      fstream tmps(tmpnm, ios_base::out);
      throw_if(!tmps);
      tmpdead = false;
      g.next([&]() { if(!tmpdead) { dbg("Removing " << tmpnm); remove(tmpnm.c_str()); } });

      string line;
      while(getline(cin, line)) {
        throw_if_not( tmps << line << endl );
      }

      tmps.close();

      throw_if(!cin.eof());
      throw_if(!tmps);
      fname = tmpnm;
    }

    dbg("Fname " << fname);
    dbg("State " << stnm);

    show_usage = false;

    lockfile(g);

    {
      dbg("Syntax " << fname);
      fstream fs(fname, ios_base::in);
      throw_if(!fs);
      apply_state(fs, a, dryrun);

      dbg("Syntax " << stnm);
      fstream f(stnm, ios_base::in);
      if(!f) {
        dbg("Warning: state " << stnm << " doesn't exist, treating as empty");
      }
      apply_state(f, a, dryrun);
    }

    bool restore = true;

    try {

      fstream fs(fname, ios_base::in);
      apply_state(fs, a, force);

      if(a.force) {

        dbg("Forcing");
        throw_if( 0 != rename(fname.c_str(), stnm.c_str()) );
        tmpdead = true;
        restore = false;

      }
      else {

        conf_t c = confirm(a);

        switch(c) {

          case confirmed:
            dbg("Confirming");
            throw_if( 0 != rename(fname.c_str(), stnm.c_str()) );
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
      fstream f(stnm.c_str(), ios_base::in);
      apply_state(f, a, force);

      exitcode = 1;
    }
    else {

      exitcode = 0;
    }
  }
  catch(string &e) {
    dbg(e);
  }
  catch(exception &e) {
    dbg(e.what());
  }
  catch(...) {
    dbg("Unknown exception");
  }

  if(exitcode != 0 && show_usage)
    usage();

  return exitcode;
}

