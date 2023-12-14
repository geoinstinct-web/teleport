// source: teleport/userpreferences/v1/assist.proto
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

goog.exportSymbol('proto.teleport.userpreferences.v1.AssistUserPreferences', null, global);
goog.exportSymbol('proto.teleport.userpreferences.v1.AssistViewMode', null, global);
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
proto.teleport.userpreferences.v1.AssistUserPreferences = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.teleport.userpreferences.v1.AssistUserPreferences.repeatedFields_, null);
};
goog.inherits(proto.teleport.userpreferences.v1.AssistUserPreferences, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  /**
   * @public
   * @override
   */
  proto.teleport.userpreferences.v1.AssistUserPreferences.displayName = 'proto.teleport.userpreferences.v1.AssistUserPreferences';
}

/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.repeatedFields_ = [1];



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
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.toObject = function(opt_includeInstance) {
  return proto.teleport.userpreferences.v1.AssistUserPreferences.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Deprecated. Whether to include
 *     the JSPB instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.teleport.userpreferences.v1.AssistUserPreferences} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.toObject = function(includeInstance, msg) {
  var f, obj = {
    preferredLoginsList: (f = jspb.Message.getRepeatedField(msg, 1)) == null ? undefined : f,
    viewMode: jspb.Message.getFieldWithDefault(msg, 2, 0)
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
 * @return {!proto.teleport.userpreferences.v1.AssistUserPreferences}
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.teleport.userpreferences.v1.AssistUserPreferences;
  return proto.teleport.userpreferences.v1.AssistUserPreferences.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.teleport.userpreferences.v1.AssistUserPreferences} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.teleport.userpreferences.v1.AssistUserPreferences}
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.addPreferredLogins(value);
      break;
    case 2:
      var value = /** @type {!proto.teleport.userpreferences.v1.AssistViewMode} */ (reader.readEnum());
      msg.setViewMode(value);
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
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.teleport.userpreferences.v1.AssistUserPreferences.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.teleport.userpreferences.v1.AssistUserPreferences} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getPreferredLoginsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      1,
      f
    );
  }
  f = message.getViewMode();
  if (f !== 0.0) {
    writer.writeEnum(
      2,
      f
    );
  }
};


/**
 * repeated string preferred_logins = 1;
 * @return {!Array<string>}
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.getPreferredLoginsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 1));
};


/**
 * @param {!Array<string>} value
 * @return {!proto.teleport.userpreferences.v1.AssistUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.setPreferredLoginsList = function(value) {
  return jspb.Message.setField(this, 1, value || []);
};


/**
 * @param {string} value
 * @param {number=} opt_index
 * @return {!proto.teleport.userpreferences.v1.AssistUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.addPreferredLogins = function(value, opt_index) {
  return jspb.Message.addToRepeatedField(this, 1, value, opt_index);
};


/**
 * Clears the list making it empty but non-null.
 * @return {!proto.teleport.userpreferences.v1.AssistUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.clearPreferredLoginsList = function() {
  return this.setPreferredLoginsList([]);
};


/**
 * optional AssistViewMode view_mode = 2;
 * @return {!proto.teleport.userpreferences.v1.AssistViewMode}
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.getViewMode = function() {
  return /** @type {!proto.teleport.userpreferences.v1.AssistViewMode} */ (jspb.Message.getFieldWithDefault(this, 2, 0));
};


/**
 * @param {!proto.teleport.userpreferences.v1.AssistViewMode} value
 * @return {!proto.teleport.userpreferences.v1.AssistUserPreferences} returns this
 */
proto.teleport.userpreferences.v1.AssistUserPreferences.prototype.setViewMode = function(value) {
  return jspb.Message.setProto3EnumField(this, 2, value);
};


/**
 * @enum {number}
 */
proto.teleport.userpreferences.v1.AssistViewMode = {
  ASSIST_VIEW_MODE_UNSPECIFIED: 0,
  ASSIST_VIEW_MODE_DOCKED: 1,
  ASSIST_VIEW_MODE_POPUP: 2,
  ASSIST_VIEW_MODE_POPUP_EXPANDED: 3,
  ASSIST_VIEW_MODE_POPUP_EXPANDED_SIDEBAR_VISIBLE: 4
};

goog.object.extend(exports, proto.teleport.userpreferences.v1);
