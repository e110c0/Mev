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

  // reverse name for given IP address
  that.arpafy = function(ip) {
    return ip.split('.').reverse().join('.').concat('.in-addr.arpa');
  };

  // finial
  that.finishRes = function(result){
    that.emit('done', result['result']);
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

  // Generate requests from data
  that.genReq = function(data){
    var reqs = [],
        iplength,
        nextip,
        d;
    // Create correct request
    if(data.nsl && !data.reqnsl){
      iplength = data.ip.split('.').length
      // 2: in-addr.arpa, 3-5: authority NS, 6: PTR
      if (iplength < 2) {
        d = {
          ip: "in-addr.arpa",
          cns: data.cns,
          nsl: data.nsl,
          reqnsl: true,
          ptr: false
        }        
        that.emit('request', d)
      } else if (iplength < 5) { // stop for full ipv4s (6) or earlier
        // Generate request for the next 256 subnets
        for(var i = 0; i<256; i++){
          d = {
            ip: i + "." + data.ip,
            cns: data.cns,
            nsl: data.nsl,
            reqnsl: (iplength < 5), // NS for all rounds but last
            ptr: (iplength == 5) // ptr for last round only
          }
          that.emit('request', d)
        }
      }
    }
  };

  // Run a given Request
  that.runReq = function(req){
    var passResult;

    var sendRequest = function(req,ns){
      var question = dns.Question({
        name: req.ip,
        type: (req.ptr) ? 'PTR' : 'NS'
      });
//      console.log(question);
      var request = dns.Request({
        question: question,
        server: { address: ns, port: 53, type: 'udp'},
        timeout: 1000
      });
      request.on('timeout', function () {
        // Construct the next request to be emitted if the current does not return
        // it is run against the next nameserver in the list if availible
        try {
          var nextns = req.nsl[1];
          if(nextns) {
            var nextreq = {
              ip: req.ip,
              cns: nextns,
              nsl: req.nsl.slice(1),
              reqnsl: req.reqnsl,
              ptr: req.ptr,
            }
            that.emit('request', nextreq);
            //console.log('Timeout in making request, trying next server in list');
          }
        } catch(err) {
          // No next request can be constructed... done here
          //console.log('Timeout in making request, and no more servers available');
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
            console.log(err);
            //throw err;
          } else {
            //console.log(addresses);
            NSCache[req.cns] = addresses[0];
            sendRequest(req, NSCache[req.cns]);
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

    if(req.ptr && !err){
      that.finishRes({result: { key:req.ip, value:res}})
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
      // create new data
      if (nsl.length > 0) {
        data = {
          ip: req.ip,
          cns: nsl[0],
          nsl: nsl,
          reqnsl: false,
          ptr: false
        }
        that.emit('data', data);
      }
    }
  };
}

// Extend EventEmitter
RDNS.prototype = new EventEmitter;

// Export
module.exports = RDNS;
