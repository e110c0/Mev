/* 
 * Extension of the default node dns.js to use passed Nameservers
 * Author of those small changes Philipp Fehre <philipp.fehre@gmail.com>  
 * 
 * IMPORTANT! METHODS NOT MARKED TESTED ARE NOT TESTED!
 * THEY PROBABLY WORK BUT ARE SIMPLY COPIED FROM THE ORIGINAL
 * NODE IMPLEMENTATION, WITHOUT TESTCODE ENSURING THE EXTENSION
 * WORKS!
 * 
 * SOFAR ONLY FOLLOWING METHODS ARE TESTED:
 * resolveNs
 * getHostByName
 *
 */

var dns = process.binding('cares');
var net = process.binding('net');
var IOWatcher = process.binding('io_watcher').IOWatcher;

var channelid = 0;
var channels = {};
var watchers = {};
var activeWatchers = {};
var Timer = process.binding('timer').Timer;

var timer = new Timer();

timer.callback = function() {
  var sockets = Object.keys(activeWatchers);
  for (var i = 0, l = sockets.length; i < l; i++) {
    var socket = sockets[i];
    var s = parseInt(socket, 10);
		for(c in channels) {
    	channels[c].processFD(watchers[socket].read ? s : dns.SOCKET_BAD,
                      	watchers[socket].write ? s : dns.SOCKET_BAD);
		}									
  }
  updateTimer();
};


function updateTimer() {
  timer.stop();
  // Were just checking to see if activeWatchers is empty or not
  if (0 === Object.keys(activeWatchers).length) return;
  var max = 20000;
  var timeout = channels[0].timeout(max);
  timer.start(timeout, 0);
}


// Create a new channel with the set DNS Server
exports.initChannelWithNs = function(ns) {
	var properties = { SOCK_STATE_CB: function(socket, read, write) {
  	var watcher, fd;
  	if (process.platform == 'win32') {
  	  fd = process.binding('os').openOSHandle(socket);
  	} else {
  	  fd = socket;
  	}
  	
  	if (socket in watchers) {
  	  watcher = watchers[socket].watcher;
  	} else {
  	  watcher = new IOWatcher();
  	  watchers[socket] = { read: read, write: write, watcher: watcher };
  	
  	  watcher.callback = function(read, write)  {
  	    channel.processFD(read ? socket : dns.SOCKET_BAD,
  	                      write ? socket : dns.SOCKET_BAD);
  	    updateTimer();
  	  };
  	}
  	
  	watcher.stop();
  	
  	if (!(read || write)) {
  	  delete activeWatchers[socket];
  	  return;
  	} else {
  	  watcher.set(fd, read == 1, write == 1);
  	  watcher.start();
  	  activeWatchers[socket] = watcher;
  	}
  	updateTimer();
	}};

	// 	If nameserver is not given as IP it needs to be resolved first
	if(ns){
		if(net.isIP(ns)!==0) {
			properties['CHANNEL_NS'] = ns;
			var channel = new dns.Channel(properties);
			channels[channelid] = channel;
		} 
	} else {
		var channel = new dns.Channel(properties);
		channels[channelid] = channel;
	}
	return channelid++;
};


exports.resolve = function(channelid, domain, type_, callback_) {
  var type, callback;
  if (typeof(type_) == 'string') {
    type = type_;
    callback = callback_;
  } else {
    type = 'A';
    callback = arguments[2];
  }

  var resolveFunc = resolveMap[type];

  if (typeof(resolveFunc) == 'function') {
    resolveFunc(channelid, domain, callback);
  } else {
    throw new Error('Unknown type "' + type + '"');
  }
};


function familyToSym(family) {
  if (family !== dns.AF_INET && family !== dns.AF_INET6) {
    family = (family === 6) ? dns.AF_INET6 : dns.AF_INET;
  }
  return family;
}

// TESTED
exports.getHostByName = function(channelid, domain, family/*=4*/, callback) {
  if (typeof family === 'function') { callback = family; family = null; }
  channels[channelid].getHostByName(domain, familyToSym(family), callback);
};


exports.getHostByAddr = function(channelid, address, family/*=4*/, callback) {
  if (typeof family === 'function') { callback = family; family = null; }
  channels[channelid].getHostByAddr(address, familyToSym(family), callback);
};


// Easy DNS A/AAAA look up
// lookup(domain, [family,] callback)
exports.lookup = function(channelid, domain, family, callback) {
  // parse arguments
  if (arguments.length === 2) {
    callback = family;
    family = undefined;
  } else if (family && family !== 4 && family !== 6) {
    family = parseInt(family, 10);
    if (family === dns.AF_INET) {
      family = 4;
    } else if (family === dns.AF_INET6) {
      family = 6;
    } else if (family !== 4 && family !== 6) {
      throw new Error('invalid argument: "family" must be 4 or 6');
    }
  }

  if (!domain) {
    callback(null, null, family === 6 ? 6 : 4);
    return;
  }

  var matchedFamily = net.isIP(domain);
  if (matchedFamily) {
    callback(null, domain, matchedFamily);
    return;
  }

  if (/\w\.local\.?$/.test(domain)) {
    // ANNOYING: In the case of mDNS domains use NSS in the thread pool.
    // I wish c-ares had better support.
    process.binding('net').getaddrinfo(domain, 4, function(err, domains4) {
      callback(err, domains4[0], 4);
    });
    return;
  }

  if (family) {
    // resolve names for explicit address family
    var af = familyToSym(family);
    channels[channelid].getHostByName(domain, af, function(err, domains) {
      if (!err && domains && domains.length) {
        if (family !== net.isIP(domains[0])) {
          callback(new Error('not found'), []);
        } else {
          callback(null, domains[0], family);
        }
      } else {
        callback(err, []);
      }
    });
    return;
  }

  // first resolve names for v4 and if that fails, try v6
  channels[channelid].getHostByName(domain, dns.AF_INET, function(err, domains4) {
    if (domains4 && domains4.length) {
      callback(null, domains4[0], 4);
    } else {
      channels[channelid].getHostByName(domain, dns.AF_INET6, function(err, domains6) {
        if (domains6 && domains6.length) {
          callback(null, domains6[0], 6);
        } else {
          callback(err, []);
        }
      });
    }
  });
};


exports.resolve4 = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.A, callback);
};


exports.resolve6 = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.AAAA, callback);
};


exports.resolveMx = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.MX, callback);
};


exports.resolveTxt = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.TXT, callback);
};


exports.resolveSrv = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.SRV, callback);
};


exports.reverse = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.PTR, callback);
};

// TESTED
exports.resolveNs = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.NS, callback);
};


exports.resolveCname = function(channelid, domain, callback) {
  channels[channelid].query(domain, dns.CNAME, callback);
};

var resolveMap = { A: exports.resolve4,
                   AAAA: exports.resolve6,
                   MX: exports.resolveMx,
                   TXT: exports.resolveTxt,
                   SRV: exports.resolveSrv,
                   PTR: exports.resolvePtr,
                   NS: exports.resolveNs,
                   CNAME: exports.resolveCname };

// ERROR CODES
exports.NODATA = dns.NODATA;
exports.FORMERR = dns.FORMERR;
exports.BADRESP = dns.BADRESP;
exports.NOTFOUND = dns.NOTFOUND;
exports.BADNAME = dns.BADNAME;
exports.TIMEOUT = dns.TIMEOUT;
exports.CONNREFUSED = dns.CONNREFUSED;
exports.NOMEM = dns.NOMEM;
exports.DESTRUCTION = dns.DESTRUCTION;
exports.NOTIMP = dns.NOTIMP;
exports.EREFUSED = dns.EREFUSED;
exports.SERVFAIL = dns.SERVFAIL;
