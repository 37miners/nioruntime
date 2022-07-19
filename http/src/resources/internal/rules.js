const RULE_TYPE_AND = 1;
const RULE_TYPE_OR = 2;
const RULE_TYPE_NOT = 3;
const RULE_TYPE_PATTERN = 4;

class Pattern {
	constructor(regex, is_multi) {
		this.regex = new TextEncoder().encode(regex);
		this.is_multi = is_multi;
		this.id = new BigInteger(String(Math.round(Math.random() * 18446744073709551615)), 10);
	}

	serialize() {
		var buffer = new ArrayBuffer(this.regex.length + 17);
		var buffer = new Uint8Array(buffer);
		u64_tobin(this.regex.length, buffer, 0);
		var offset = 8;
		for(var i=0; i<this.regex.length; i++) {
			buffer[offset] = this.regex[i];
			offset += 1;
		}
		u64_tobin(this.id, buffer, offset);
		if(this.is_multi) {
			buffer[offset+8] = 1;
		} else {
			buffer[offset+8] = 0;
		}
		return buffer;
	}

	deserialize(buffer, offset) {
		var length = to_u64(buffer, offset);
		this.regex = new ArrayBuffer(length);
		this.regex = new Uint8Array(this.regex);
		offset += 8;
		for(var i=0; i<length; i++) {
			this.regex[i] = buffer[offset];
			offset += 1;
		}
		this.id = to_u64(buffer, offset);
		offset += 8;
		if(buffer[offset] == 0) {
			this.is_multi = false;
		} else {
			this.is_multi = true;
		}
		offset += 1;
		return offset;
	}

	toString() {
		return "Pattern(regex='" +
			new TextDecoder().decode(this.regex) +
			"',is_multi=" + this.is_multi +
			",id="+ this.id + ")";
	}
}

class Rule {
	constructor(rule_type, b, c) {
		this.rule_type = rule_type;
		 if (rule_type == RULE_TYPE_PATTERN) {
			this.pattern = new Pattern(b, c);

		 } else {
			this.rules = b;
		 }
	}

	serialize() {
		if (typeof this.pattern != 'undefined') {
			var pattern_buf = this.pattern.serialize();
			var ret = new ArrayBuffer(pattern_buf.length + 1);
			var ret = new Uint8Array(ret);
			ret[0] = RULE_TYPE_PATTERN;
			for(var i=0; i<pattern_buf.length; i++) {
				ret[i+1] = pattern_buf[i];
			}
			return ret;
		} else {
			if(this.rule_type == RULE_TYPE_NOT) {
				var rule = this.rules[0].serialize();
				var ret = new ArrayBuffer(rule.length + 1);
				var ret = new Uint8Array(ret);
				ret[0] = RULE_TYPE_NOT;
				for(var i=0; i<rule.length; i++) {
					ret[i+1] = rule[i];
				}
				return ret;
			} else {
				var len = 0;
				var ser_rules = [];
				var rules = this.rules;
				for(var i=0; i<rules.length; i++) {
					var rule = rules[i];
					var rule_ser = rule.serialize();
					len += rule_ser.length;
					ser_rules.push(rule_ser);
				}
				var ret = new ArrayBuffer(len + 9);
				var ret = new Uint8Array(ret);
				ret[0] = this.rule_type;
				u64_tobin(this.rules.length, ret, 1);
				var offset = 9;

				for(var i=0; i<ser_rules.length; i++) {
					var rule = ser_rules[i];
					for(var j=0; j<rule.length; j++) {
						ret[offset+j] = rule[j];
					}
					offset += rule.length;
				}
				return ret;
			}
		}
	}

	deserialize(buffer, offset) {
		this.rule_type = buffer[offset];
		if(buffer[offset] == RULE_TYPE_PATTERN) {
			this.pattern = new Pattern();
			return this.pattern.deserialize(buffer, offset+1);
		} else if(buffer[offset] == RULE_TYPE_NOT) {
			this.rules = [];
			var rule = new Rule();
			var noffset = rule.deserialize(buffer, offset+1);
			this.rules.push(rule);

			return noffset;
		} else if(buffer[offset] == RULE_TYPE_AND || buffer[offset] == RULE_TYPE_OR) {
			var count = to_u64(buffer, offset+1);
			offset += 9;
			this.rules = [];
			for(var i=0; i<count; i++) {
				var rule = new Rule();
				offset = rule.deserialize(buffer, offset);
				this.rules.push(rule);
			}
			return offset;
		} else {
			throw "Unknown rule type = " + buffer[offset] + " at offset = " + offset;
		}
	}

	toString() {
		if(this.rule_type == RULE_TYPE_PATTERN) {
			return "Rule(" + this.pattern + ")";
		} else if(this.rule_type == RULE_TYPE_NOT) {
			return "Rule(Not(" + this.rules[0] + "))";
		} else if(this.rule_type == RULE_TYPE_AND) {
			var ret = "Rule(" + this.rules[0];
			for(var i=1; i<this.rules.length; i++) {
				ret += " and " + this.rules[i];
			}
			ret += ")";
			return ret;
		} else if(this.rule_type == RULE_TYPE_OR) {
			var ret = "Rule(" + this.rules[0];
                        for(var i=1; i<this.rules.length; i++) {
                                ret += " or " + this.rules[i];
                        }
                        ret += ")";
                        return ret;
		} else {
			return "unknown rule type = " + this.rule_type;
		}
	}
}

