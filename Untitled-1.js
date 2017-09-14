exports.read = function (data, key, externalAAD) {
  externalAAD = externalAAD || EMPTY_BUFFER;

  return cbor.decodeFirst(data)
  .then((obj) => {
    if (obj instanceof Tagged) {
      if (obj.tag !== MAC0Tag) {
        throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
      }
      obj = obj.value;
    }

    if (!Array.isArray(obj)) {
      throw new Error('Expecting Array');
    }

    if (obj.length !== 4) {
      throw new Error('Expecting Array of lenght 4');
    }

    let [p, u, payload, tag] = obj;
    p = cbor.decode(p);
    p = (!p.size) ? EMPTY_BUFFER : p;
    u = (!u.size) ? EMPTY_BUFFER : u;

    if (p == EMPTY_BUFFER){

      const alg = u.get(common.HeaderParameters.alg);
    }else{
      for (var key in AlgFromTags){     
        if (key == p.get(1)){
          var alg = key;
        }
      }  
    }
    return doMac('MAC0', p, externalAAD, payload, COSEAlgToNodeAlg[AlgFromTags[alg]], key)
    .then((calcTag) => {
      if (tag.toString('hex') !== calcTag.toString('hex')) {
        throw new Error('Tag mismatch');
      }
      return payload;
    });
  });
};
