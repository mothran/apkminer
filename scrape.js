var gplay = require('google-play-scraper');
gplay.list({
    category: gplay.category.GAME_ACTION,
    collection: gplay.collection.TOP_FREE,
    num: 120
  })
  .then(function(apps){
    apps.forEach(function(item) {
      console.log(item.appId);
    });
  })
  .catch(function(e){
    console.log('There was an error fetching the list!');
  });