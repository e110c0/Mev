#!/usr/bin/env node

(function() {

/* Reverse DNS resolver script for command line use
   * Author: Philipp Fehre <philipp.fehre@googlemail.com>
   * 
   * Provide a way to parallely resolve a massive number of Reverse DNS Requests
   * Uses Redis to Store requests as well as results or write to csv file
   * 
   * Usage see mev -h
   *
   * This is part of the iStrukta Project for internet analyzation (http://measr.net/)
   */

  var Mev = require('../lib/mev'),
      sys = require('sys'),
      fs = require('fs'),
      net = require('net'),
      nomnom = require('nomnom'),
      Mev = require('../lib/mev'),
      Rdns = require('../lib/rdns');
  
  nomnom.command('rdns')
    .options({
      file: {
        abbr: 'f',
        flag: true,
        help: 'specify output and input as a file'
      },
      host: {
        metavar: 'HOST',
        help: 'specify host for tcp socket, defaults to localhost'
      },
      input: {
        abbr: "i",
        metavar: "INPUT",
        required: true,
        help: 'Input is read from this. default: socket, if -f is specified this is a file'
      },
      output: {
        abbr: "o",
        metavar: "OUTPUT",
        required: true,
        help: 'output is written to this. default: socket, if -f is given this is a file'
      },
      debug: {
         abbr: 'd',
         flag: true,
         help: "Print debugging info"
      }
    })
    .callback(function(opts){
      // Setup and start mev
      function initMev(ind, outd, flags) {
        var module = new Rdns('rdns'),
            mev = new Mev(module, ind, outd, flags);
        mev.init();
      }
      // Setup input / output
      if (opts.file) {
        // Input and output as file 
        var flags = {
          debug: opts.debug,
          file: true,
          timeout: 10000
          };
        initMev(opts.input, opts.output, flags);
      } else {
        // Open input / output either beeing unix or tcp socket
        var si = net.createServer()
        // Input socket
        if (parseFloat(opts.input)) {
          si.listen(parseFloat(opts.input), 'localhost', function() {
            var flags = {
              debug: opts.debug,
              file: false,
              timeout: 10000
            };
          initMev(opts.input, opts.output, flags);
          });
        } else {
          try {
            si.listen(opts.input, function() {
              var flags = {
                debug: opts.debug,
                file: false,
                timeout: 10000
              };
            initMev(opts.input, opts.output, flags);
            });
          } catch (err) {
            console.log('Path to unix input socket is invalid');
          }
        }
      }
    })
    .help('run a reverse DNS NS authority resolution');
  nomnom.parse();

})()
