// source: teleport/userpreferences/v1/cluster_preferences.proto
/**
 * @fileoverview
 * @enhanceable
 * @suppress {missingRequire} reports error on implicit type usages.
 * @suppress {messageConventions} JS Compiler reports an error if a variable or
 *     field starts with 'MSG_' and isn't a translatable message.
 * @public
 */
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck

var jspb = require('google-protobuf');
var goog = jspb;
var global = (function() { return this || window || global || self || Function('return this')(); }).call(null);

goog.exportSymbol('proto.teleport.userpreferences.v1.ClusterUserPreferences', null, global);
goog.exportSymbol('proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences', null, global);
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.repeatedFields_, null);
};
goog.inherits(proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.displayName = 'proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences';
}
/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.teleport.userpreferences.v1.ClusterUserPreferences, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.teleport.userpreferences.v1.ClusterUserPreferences.displayName = 'proto.teleport.userpreferences.v1.ClusterUserPreferences';
}

/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.prototype.toObject = function(opt_includeInstance) {
  return proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.toObject = function(includeInstance, msg) {
  var f, obj = {
    resourceIdsList: (f = jspb.Message.getRepeatedField(msg, 1)) == null ? undefined : f
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences}
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences;
  return proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences}
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.addResourceIds(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getResourceIdsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      1,
      f
    );
  }
};


/**
 * repeated string resource_ids = 1;
 * @return {!Array<string>}
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.prototype.getResourceIdsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 1));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.prototype.setResourceIdsList = function(value) {
  return jspb.Message.setField(this, 1, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.prototype.addResourceIds = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 1, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.prototype.clearResourceIdsList = function() {
  return this.setResourceIdsList([]);
};





if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * Optional fields that are not set will be set to undefined.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     net/proto2/compiler/js/internal/generator.cc#kKeyword.
 * @param {boolean=} opt_includeInstance Deprecated. whether to include the
 *     JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @return {!Object}
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.prototype.toObject = function(opt_includeInstance) {
  return proto.teleport.userpreferences.v1.ClusterUserPreferences.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.teleport.userpreferences.v1.ClusterUserPreferences} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.toObject = function(includeInstance, msg) {
  var f, obj = {
    pinnedResources: (f = msg.getPinnedResources()) && proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.toObject(includeInstance, f)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.teleport.userpreferences.v1.ClusterUserPreferences}
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.teleport.userpreferences.v1.ClusterUserPreferences;
  return proto.teleport.userpreferences.v1.ClusterUserPreferences.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.teleport.userpreferences.v1.ClusterUserPreferences} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.teleport.userpreferences.v1.ClusterUserPreferences}
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences;
      reader.readMessage(value,proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.deserializeBinaryFromReader);
      msg.setPinnedResources(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.teleport.userpreferences.v1.ClusterUserPreferences.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.teleport.userpreferences.v1.ClusterUserPreferences} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getPinnedResources();
  if (f != null) {
    writer.writeMessage(
      1,
      f,
      proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences.serializeBinaryToWriter
    );
  }
};


/**
 * optional PinnedResourcesUserPreferences pinned_resources = 1;
 * @return {?proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences}
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.prototype.getPinnedResources = function() {
  return /** @type{?proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences} */ (
    jspb.Message.getWrapperField(this, proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences, 1));
};


/**
 * @param {?proto.teleport.userpreferences.v1.PinnedResourcesUserPreferences|undefined} value
 * @return {!proto.teleport.userpreferences.v1.ClusterUserPreferences} returns this
*/
proto.teleport.userpreferences.v1.ClusterUserPreferences.prototype.setPinnedResources = function(value) {
  return jspb.Message.setWrapperField(this, 1, value);
};


/**
 * Clears the message field making it undefined.
 * @return {!proto.teleport.userpreferences.v1.ClusterUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.prototype.clearPinnedResources = function() {
  return this.setPinnedResources(undefined);
};


/**
 * Returns whether this field is set.
 * @return {boolean}
 */
proto.teleport.userpreferences.v1.ClusterUserPreferences.prototype.hasPinnedResources = function() {
  return jspb.Message.getField(this, 1) != null;
};


goog.object.extend(exports, proto.teleport.userpreferences.v1);
