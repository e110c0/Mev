/* Reverse DNS measurement module for Mev
 * Author: Philipp Fehre <philipp.fehre@googlemail.com>
 * Rewrite for node 0.8 and native-dns by: Dirk Haage <dirk@haage.info>
 *
 * Provide a way to parallely resolve a massive number of Reverse DNS Requests
 * Uses Redis to Store requests as well as results
 *
 * This is part of the iStrukta Project for internet analyzation
 *
 */

var mev = require(__dirname + '/mev'),
    EventEmitter = require('events').EventEmitter,
    dns = require("native-dns"),
    net = require("net"),
    sys = require('sys');

var NSCache = {};

function RDNS(id, timeout) {

  var that = this,
      _timeout;

  that.id = id;


  // finial
  that.finishRes = function(result){
    //that.emit('done', result['result']);
  };

  // read input
  that.readInput = function(indata){
    var ip,
        ns,
        data;
    var nsl = [];

    indata.split(',').forEach( function(el, idx, ary){
      var e = el.trim();
      (idx == 0) ? ip = e : nsl.push(e);

    });

    if(nsl.length === 0) {
      ns = undefined;
      nsl = undefined;
    } else {
      ns = nsl[0];
    }

    data = { ip: ip, cns: ns, nsl: nsl };
    that.emit('data', data);
  };

  // Generate request round based on last result
  that.generateNextRound = function(host,nsl){
    var reqs = [],
        namelength = host.split('.').length,
        d;
    // Create correct request
    // 2: in-addr.arpa, 3-5: authority NS, 6: PTR
    if (namelength < 6) { // stop for full ipv4s (6) or earlier
      // Generate request for the next 256 subnets
      for(var i = 0; i<256; i++){
        nsl.sort(function() {return 0.5 - Math.random()})
        d = {
          ip: i + "." + host,
          cns: nsl[0],
          nsl: nsl,
          reqnsl: (namelength < 5), // NS for all rounds but last
          ptr: (namelength == 5) // ptr for last round only
        }
        that.emit('request', d)
      }
    }
  }
  // Generate requests from data
  that.genReq = function(data){
    var iplength = data.ip.split('.').length
    // 2: in-addr.arpa, 3-5: authority NS, 6: PTR
    var d = {
      ip: data.ip,
      cns: data.cns,
      nsl: data.nsl,
      reqnsl: (iplength < 6), // NS for all rounds but last
      ptr: (iplength == 6) // ptr for last round only
    }
    that.emit('request', d)
  };

  // Run a given Request
  that.runReq = function(req){
    var passResult;

    var sendRequest = function(req,ns){
      var question = dns.Question({
        name: req.ip,
        type: (req.ptr) ? 'PTR' : 'NS'
      });
      //console.log(question);
      var request = dns.Request({
        question: question,
        server: { address: ns, port: 53, type: 'udp'},
        timeout: 2000
      });
      request.on('timeout', function () {
        // Construct the next request to be emitted if the current does not return
        // it is run against the next nameserver in the list if availible
        try {
          var nextreq = {
            ip: req.ip,
            cns: req.nsl[1],
            nsl: req.nsl.slice(1),
            reqnsl: req.reqnsl,
            ptr: req.ptr,
          }
          //console.log('Timeout in making request for ' + req.ip + ', trying next server in list: ' + req.nsl);
          that.emit('request', nextreq);
        } catch(err) {
          // No next request can be constructed... done here
          //console.log(err)
          //console.log('Timeout in making request for ' + req.ip + ', and no more servers available');
        }
      });
      request.on('message', function (err, answer) {
        that.emit('result', { req: req, res: answer });
      });
      request.send();
    };
    
    if (net.isIP(req.cns)) {
      sendRequest(req, req.cns);
    } else {
      if (NSCache[req.cns]) {
        sendRequest(req, NSCache[req.cns]);
      } else {
        dns.resolve4(req.cns, function(err, addresses) {
          if (err) {
            //console.log(err);
            //throw err;
          } else {
            //console.log(addresses);
            if (addresses.length > 0) {
              NSCache[req.cns] = addresses[0];
              sendRequest(req, NSCache[req.cns]);              
            } else {
              // remove frist NS and create new request
              try {
                var nextreq = {
                  ip: req.ip,
                  cns: req.nsl[1],
                  nsl: req.nsl.slice(1),
                  reqnsl: req.reqnsl,
                  ptr: req.ptr,
                }
                //console.log('Timeout in making request for ' + req.ip + ', trying next server in list: ' + req.nsl);
                that.emit('request', nextreq);
              } catch(err) {
                // No next request can be constructed... done here
                //console.log(err)
                //console.log('Timeout in making request for ' + req.ip + ', and no more servers available');
              }
            }
          }
        });
      }
    }
  };

  // Handle the result returned form a request
  that.handleRes = function(data){
    var req = data.req,
        res = data.res,
        err = data.error,
        data;

    if(req.ptr && !err && res.answer.length > 0){
      that.finishRes({result: { key:req.ip, value:res}})
      console.log(req.ip + ' => ' + res.answer[0].data);
    }
    if(req.reqnsl && !err){
      // get all authorative nameservers
      var nsl = [];
      res.answer.forEach(function (a) {
        if (a.data && a.name === req.ip) {
          nsl.push(a.data.trim().toLowerCase());
        } else {
          //console.log("got bullshit: " + JSON.stringify(a));
        }
      });
      res.authority.forEach(function (a) {
        if (a.data && a.name === req.ip) {
          nsl.push(a.data.trim().toLowerCase());
        } else {
          //console.log("got bullshit: " + JSON.stringify(a));
        }
      });
      // log result
      console.log(req.ip + ': ' + JSON.stringify(nsl));
      // create new request (not data, data is from input only)
      if (nsl.length > 0) that.generateNextRound(req.ip,nsl);
    }
  };
}

// Extend EventEmitter
RDNS.prototype = new EventEmitter;

// Export
module.exports = RDNS;
