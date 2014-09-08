#include <stdio.h>
#include <stdlib.h>
#include <shadow.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
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
using namespace std::placeholders;

static string g_dmode = "?";

FILE* popen_no_exec(const char *a1, const char* a2) {
  FILE* f = popen(a1,a2);
  if(f) {
    if(fcntl(fileno(f), F_SETFD, FD_CLOEXEC) != 0) {
      fclose(f);
      f = NULL;
    }
  }
  return f;
}

static inline std::string mks_(function<void(ostringstream &oss)> f) {
  ostringstream oss;
  f(oss);
  return oss.str();
}

#define ss(x) mks_([&](std::ostringstream &oss){ oss << x ;})

static bool g_haslog = false;

#define dbg_stderr(ss) do{ cerr <<  "setman[" << g_dmode << "]: " << __func__ << ":" <<  __LINE__ << ": " << ss << endl; } while(0)

#define log(s,x) do{ \
  if(g_haslog) \
    syslog(LOG_USER|(x), "%s:%d:%s", __func__, __LINE__, ss(s).c_str()); \
  else \
    dbg_stderr(s); \
  } while(0)

#define dbg(s) log(s,LOG_NOTICE)
#define err(s) log(s,LOG_ERR)

#define throw_(s) do{ int _errno = errno; throw string( ss( __func__ << ":" << __LINE__ << ":e" << _errno << ": " << s)); } while(0)
#define throw_if(cnd) do{ if(cnd){ throw_( #cnd ); } } while(0)
#define throw_if_not(cnd) throw_if(!(cnd))

inline void in_try_catch(std::function<void()> f) {
    try{
      f();
    }
    catch(std::exception &e) {
      err("exception " << e.what());
      assert(false);
    }
    catch(...) {
      err("exception '...'");
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
  if(ip == "" || ip == "-" || ip == "0.0.0.0")
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
  int ec = WEXITSTATUS(ret);
  dbg("\"" << s << "\" ret " << ret << " ec " << ec);
  throw_if(ec != 0);
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
    sys(SETMAN_IPTABLES " -A INPUT -p udp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT");
    sys(SETMAN_IPTABLES " -A INPUT -p udp --sport 123 -j ACCEPT");
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

        if(gw != "-" && gw != "0.0.0.0") {
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
      throw_if_not( s >> ip >> mask );
      throw_if( s >> e );

      ip_check(ip);
      ip_check(mask);

      if(mode == force) {
        sys( ss(SETMAN_IPTABLES << " -A INPUT -s '" << ip << "/" << mask << "' -j ACCEPT"));
      }
    }
    else {
      return false;
    }

    return true;
  });
}

void with_user(cmdmode_t mode, const args &a, function< void( fchecker_t ) > f) {

  FILE *pp = NULL;

  if(mode == force) {
    pp = popen_no_exec(SETMAN_UPWD, "we");
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

void with_serial(cmdmode_t mode, const args &a, function< void( fchecker_t ) > f) {

  if(mode == force) {
  }

  f([&](string cmd, istream &s) {
    if (cmd == "serial") {
      string line;
      getline(s, line);

      if(mode == force) {

        sys( ss(SETMAN_SERIAL << " " << line) );

      }
    }
    else {
      return false;
    }

    return true;
  });
}


void with_syslog(cmdmode_t mode, const args &a, function< void ( fchecker_t ) > f) {

  int nsyslog = 0;

  if(mode == force) {
    sys( ss(SETMAN_SYSLOG) );
  }

  f([&](string cmd, istream &s) {
    if (cmd == "syslog") {
      int port;
      string host, e;
      s >> host >> port;

      throw_if( s >> e );
      ip_check(host);

      if(nsyslog < 2) {

        if(ip_enabled(host)) {

          if(mode == force) {
            sys( ss(SETMAN_SYSLOG << " -R " << host << ":" << port) );
          }
        }

        nsyslog++;
      }
      else {
        throw_("only one syslog server is supported at the moment");
      }
    }
    else {
      return false;
    }

    return true;
  });

}

void with_time(cmdmode_t mode, const args &a, function< void ( fchecker_t ) > f) {

  f([&](string cmd, istream &s) {
    if (cmd == "time") {
      time_t sec;
      suseconds_t usec;
      string e;
      throw_if_not( s >> sec >> usec );
      throw_if( s >> e );

      if(mode == force) {
        struct timeval tv;
        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = sec;
        tv.tv_usec = usec;

        throw_if(0 != settimeofday(&tv, NULL));
        sys( ss(SETMAN_HWCLOCK << " -w") );

      }
    }
    else {
      return false;
    }

    return true;
  });

}

/* 'confirm' command, marking configuration as 'good' */
void with_confirm(cmdmode_t mode, const args &a, bool &confirmed, function< void ( fchecker_t ) > f) {

  confirmed = false;

  f([&](string cmd, istream &s) {
    if (cmd == "confirm") {
      string e;
      throw_if( s >> e );
      confirmed = true;
      return true;
    }
    else {
      return false;
    }
  });

}

typedef function<void(istream&, const args&, cmdmode_t)> fapplier_t;

void apply_state_all(istream &fs, const args &a, cmdmode_t mode) {

  bool confirmed = false;

  with_ip(mode, a, [&](fchecker_t ip_chk) {

  with_user(mode, a, [&](fchecker_t user_chk) {

  with_serial(mode, a, [&](fchecker_t serial_chk) {

  with_syslog(mode, a, [&](fchecker_t syslog_chk) {

  with_time(mode, a, [&](fchecker_t time_chk) {

  with_confirm(mode, a, confirmed, [&](fchecker_t confirm_chk) {

    string line;
    while(getline(fs, line)) {

      dbg("Command" << (mode == dryrun ? " (dryrun): " : ": ") << line );

      string cmd;
      istringstream s(line);

      throw_if_not( s >> cmd );

      if(ip_chk(cmd, s))
        continue;
      else if(user_chk(cmd, s))
        continue;
      else if(serial_chk(cmd, s))
        continue;
      else if(syslog_chk(cmd, s))
        continue;
      else if(time_chk(cmd, s))
        continue;
      else if(confirm_chk(cmd, s))
        continue;
      else  {
        throw_("Invalid command '" << cmd << "'");
      }
    }

  });

  });

  });

  });

  });

  });

  throw_if_not(confirmed);
}

template<class T>
void apply_state_1(T f, istream &fs, const args &a, cmdmode_t mode) {

  bool confirmed = false;

  f(mode, a, [&](fchecker_t chk) {

  with_confirm(mode, a, confirmed, [&](fchecker_t confirm_chk) {


    string line;
    while(getline(fs, line)) {

      dbg("Command" << (mode == dryrun ? " (dryrun): " : ": ") << line );

      string cmd;
      istringstream s(line);

      throw_if_not( s >> cmd );

      if(chk(cmd, s))
        continue;
      else if (confirm_chk(cmd, s))
        continue;
      else  {
        throw_("Invalid command '" << cmd << "'");
      }
    }

  });

  });

  throw_if_not(confirmed);
}

void apply_state_net(istream &fs, const args &a, cmdmode_t mode) {
  apply_state_1(with_ip, fs, a, mode);
}

void apply_state_serial(istream &fs, const args &a, cmdmode_t mode) {
  apply_state_1(with_serial, fs, a, mode);
}

void apply_state_user(istream &fs, const args &a, cmdmode_t mode) {
  apply_state_1(with_user, fs, a, mode);
}

void apply_state_syslog(istream &fs, const args &a, cmdmode_t mode) {
  apply_state_1(with_syslog, fs, a, mode);
}

void apply_state_time(istream &fs, const args &a, cmdmode_t mode) {
  apply_state_1(with_time, fs, a, mode);
}

void lockfile(guard &g, const string &lf) {
  int lockfd = open ( lf.c_str(), O_RDONLY | O_NOCTTY | O_NOFOLLOW | O_CREAT | O_CLOEXEC, 0666 );
  throw_if(lockfd < 0);
  g.next( [=]() { close(lockfd); } );
  throw_if( 0 != flock(lockfd, LOCK_EX | LOCK_NB ));
  g.next( [=]() { dbg("Unlocking"); flock(lockfd, LOCK_UN); } );
}

typedef enum { commited, rejected } conf_t;

volatile bool sigint = false;
volatile bool sigusr1 = false;

conf_t wait_commit(const args &a) {

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
    return commited;
  else {
    if(s == a.wait_sec) {
      dbg("Timeout");
    }
    return rejected;
  }
}

void usage()  {
  cerr << endl;
  cerr << "Setman reset default system settings and/or applies new one" << endl << endl;
  cerr << "Usage: setman -e ETH [-w SEC] [-f] [-m mode] MOREARGS ([-c|-r]]|(-|FILE))" << endl;
  cerr << "         -e ETH   Network interface" << endl;
  cerr << "         -w SEC   Wait SEC seconds for confirmation" << endl;
  cerr << "                  (Default: " << DEFAULT_WAIT << " secons)" << endl;
  cerr << "         -f       Force applying, don't wait for confirmation" << endl;
  cerr << "         -c       Commit uncommited changes" << endl;
  cerr << "         -r       Rollback uncommited changes" << endl;
  cerr << "         -q       Be quiet (almost)" << endl;
  cerr << "         -m mode  Operate on a subset of settings" << endl;
  cerr << "            mode is one of (net,serial,syslog,all,user,time)" << endl;
  cerr << "         --stress-sleep SEC  emulate delay for SEC seconds" << endl;
  cerr << "         FILE     New command file" << endl;
  cerr << "Signals:" << endl;
  cerr << "         SIGUSR1 Confirm the changes" << endl;
  cerr << "Files:" << endl;
  cerr << "         PID file:   " << SETMAN_PIDFILE << endl;
  cerr << "         State:      " << SETMAN_STATE << "[.mode]" << endl;
  cerr << "         Lock file:  " << SETMAN_LOCKFILE << " (access via flock)" << endl;
  exit(3);
}

typedef enum {commit, rollback, apply} act_t;

int main(int argc, char **argv) {

  int exitcode = 2;
  bool show_usage = true;
  bool quiet = false;

  /* For debugging */
  size_t dbgsleep = 0;

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
    act_t act = apply;

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
      else if(string(argv[i]) == "-c" || string(argv[i]) == "--commit") {
        act = commit;
      }
      else if(string(argv[i]) == "-r" || string(argv[i]) == "--rollback") {
        act = rollback;
      }
      else if(string(argv[i]) == "-q" || string(argv[i]) == "--quiet") {
        quiet = true;
      }
      else if(string(argv[i]) == "--stress-sleep") {
        throw_if(++i >= argc);
        dbgsleep = stoi(argv[i]);
      }
      else {
        fname = string(argv[i]);
      }
    }

    fapplier_t apply_state = apply_state_all;

    if(mode == ".serial") {
      apply_state = apply_state_serial;
    }
    else if (mode == ".user") {
      apply_state = apply_state_user;
    }
    else if (mode == ".net") {
      apply_state = apply_state_net;
    }
    else if (mode == ".syslog") {
      // apply_state = bind(apply_state_1<with_syslog>, with_syslog, _1, _2, _3);
      apply_state = apply_state_syslog;
    }
    else if (mode == ".time") {
      apply_state = apply_state_time;
    }
    else if (mode == ".all" || mode == "") {
      apply_state = apply_state_all;
      g_dmode = "all";
    }
    else {
      throw_("Invalid mode " << mode);
    }

    openlog("setman", (quiet ? 0 : LOG_PERROR)|LOG_PID|LOG_NDELAY, LOG_NOTICE);
    g_haslog = true;
    dbg("mode " << g_dmode << " force " << a.force << " fname " << fname);

    guard g;

    switch(act) {
      case apply: {

        /* Ugly, but safe */
        show_usage = false;
        lockfile(g, SETMAN_LOCKFILE + mode);
        show_usage = true;
        
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
        else {
          string f = fname;
          atret( dbg("Removing " << f); remove(f.c_str()); );
          ifstream src(fname, ios::binary);
          throw_if(!src);
          ofstream dest(tmpnm, ios::binary);
          throw_if(!dest);
          tmpdead = false;
          g.next([&]() { if(!tmpdead) { dbg("Removing " << tmpnm); remove(tmpnm.c_str()); } });
          dbg("Copying from " << fname << " to " << tmpnm);
          dest << src.rdbuf();
          src.close();
          dest.close();
          fname = tmpnm;
        }

        show_usage = false;

        dbg("fname " << fname);
        dbg("stnm " << stnm);
        bool stnm_checked = false;

        {
          dbg("Checking syntax of " << fname);
          fstream fs(fname, ios_base::in);
          throw_if(!fs);
          apply_state(fs, a, dryrun);

          dbg("Checking sysntax of  " << stnm);
          fstream f(stnm, ios_base::in);
          if(f) {
            apply_state(f, a, dryrun);
            stnm_checked = true;
          }
          else {
            dbg("Warning: state " << stnm << " doesn't exist, ignoring");
          }
        }

        bool restore = true;

        if(dbgsleep>0) {
          dbg("Going to sleep for " << dbgsleep << " seconds");
          sleep(dbgsleep);
        }

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

            conf_t c = wait_commit(a);

            switch(c) {

              case commited:
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
          dbg("Exception: " << e);
        }
        catch(exception &e) {
          dbg("Exception: " << e.what());
        }

        if(restore) {
          dbg("Rolling back");
          if(stnm_checked) {
            fstream f(stnm.c_str(), ios_base::in);
            apply_state(f, a, force);
          }
          else {
            dbg("Applying null state");
            istringstream nullconfig("confirm\n");
            apply_state(nullconfig, a, force);
          }

          exitcode = 1;
        }
        else {

          exitcode = 0;
        }
        break;
      }

      case commit:
      case rollback: {

        if(dbgsleep>0) {
          dbg("Going to sleep for " << dbgsleep << " seconds");
          sleep(dbgsleep);
        }

        throw_if( fname != "" );
        throw_if( a.eth != "" );

        fstream pidf(SETMAN_PIDFILE, ios_base::in);
        int pid;
        throw_if_not( pidf >> pid );
        int ret = kill(pid, act == commit ? SIGUSR1 : SIGINT);
        throw_if(ret != 0);
        exitcode = 0;
        break;
      }

      default:
        throw_("Invalid action: " << act);
    }

  }
  catch(string &e) {
    err("Exception: " << e);
  }
  catch(exception &e) {
    err("Exception: " << e.what());
  }
  catch(...) {
    err("Exception unknown");
  }

  if(exitcode != 0 && show_usage)
    usage();

  return exitcode;
}

