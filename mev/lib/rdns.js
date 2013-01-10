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
      if (data.ip === "in-addr.arpa") {
        d = {
          ip: data.ip,
          cns: data.cns,
          nsl: data.nsl,
          reqnsl: true,
          ptr: false
        }
        that.emit('request', d)
      } else if (iplength < 2) { // stop for full ipv4s (4) or earlier
        // Generate request for the next 256 subnets
        for(var i = 0; i<256; i++){
          if (iplength == 0) {
            nextip = i;
          } else {
            nextip = data.ip + '.' + i
          }
          d = {
            ip: nextip,
            cns: data.cns,
            nsl: data.nsl,
            reqnsl: true,
            ptr: (iplength == 3) // ptr for last round only
          }
          that.emit('request', d)
        }
      }
    }
  };

  // Run a given Request
  that.runReq = function(req){
    var nextreq,
        channel,
        td,
        nextns,
        passResult;

    var question = dns.Question({
      name: (req.ip == "in-addr.arpa") ? req.ip : that.arpafy(req.ip),
      type: (req.ptr) ? 'PTR' : 'NS'
    });

    var request = dns.Request({
      question: question,
      server: { address: req.cns, port: 53, type: 'udp'},
      timeout: 1000
    });
    console.log(question);
    request.on('timeout', function () {
      console.log('Timeout in making request');
      // Construct the next request to be emitted if the current does not return
      // it is run against the next nameserver in the list if availible
      try {
        nextns = req.nsl[1];
        if(nextns) {
          nextreq = {
            ip: req.ip,
            cns: nextns,
            nsl: req.nsl.slice(1),
            reqnsl: req.reqnsl,
            ptr: req.ptr,
          }
          that.emit('request', nextreq);
        }
      } catch(err) {
        // No next request can be constructed... done here
      }
    });
    request.on('message', function (err, answer) {
      that.emit('result', { req: req, res: answer });
    });
    request.send();

/*
    if(typeof(that.channels[req.cns]) === 'undefined') {
      // The nameserver is not present yet
      if(req.reqnsl ) {
        // A nameserver list is to be requested
        dolookup(that.channels.main);
      } else {
        // The nameserver needs to be looked up afterwards the request is run
        dnsext.getHostByName(that.channels.main, req.cns, function(err, domains){
          if(!err) {
            req.cns = domains[0];
            that.channels[domains[0]] = dnsext.initChannelWithNs(domains[0]);
            dolookup(that.channels[domains[0]]);
          }
        });
      }
    } else {
      dolookup(that.channels[req.cns]);
    }*/
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
          console.log("got bullshit: " + JSON.stringify(a));
        }
      });
      res.authority.forEach(function (a) {
        if (a.data && a.name === req.ip) {
          nsl.push(a.data.trim().toLowerCase());
        } else {
          console.log("got bullshit: " + JSON.stringify(a));
        }
      });
      // log result
      console.log(req.ip + ': ' + JSON.stringify(nsl));
      // create new data
      if (nsl.length > 0) {
        data = {
          ip: req.ip,
          cns: res[0],
          nsl: res,
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
