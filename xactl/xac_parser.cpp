#include <fstream>
#include <iostream>
#include <utility>
#include <vector>
#include <string>
#include <map>
#include <deque>

#include "xac_common.h"
#include "xac_parser.h"
#include "crypto_utils.hpp"
#include "fs_utils.hpp"


namespace {

using std::deque;
using std::vector;
using std::map;
using std::string;
using std::shared_ptr;
using namespace std::literals;

enum {
	kSPCanary = 0x9c8954035248467a,
	kOPCanary = 0x7c9f88fc
};

enum Type: uint32_t {
	XAC_SUBJECT,
	XAC_OBJECT,
	XAC_TYPE_MAX
};

enum Flags: uint32_t {
	READ 		= 0x01,
	WRITE 		= 0x02,
	EXECUTE 	= 0x04,
	ALLOW 		= 0x08,
	LOG 		= 0x10
};

struct token {
	enum class Type {
		BAD_TOKEN,
		SUB_TOKEN,
		OBJ_TOKEN,
		PATH,
		INVERT,
		ACCESS,
		ASTERISK,
		HASH,
		LOG_TOKEN,
		WS,
		TAB,
		NEW_LINE,
		EOF_TOKEN,
	};

	static string names[];

	Type type;
	std::string val;
	uint32_t line;
	uint32_t col;
};

string token::names [] = {
	"BAD_TOKEN",
	"SUB",
	"OBJ",
	"PATH",
	"INVERT",
	"ACCESS",
	"ASTERISK",
	"HASH",
	"LOG",
	"WS",
	"TAB",
	"NEW_LINE",
	"EOF"
};

using TokenType = token::Type;

string
token2str(TokenType t)
{
	return token::names[static_cast<int>(t)];
}

std::ostream&
operator<<(std::ostream &os, TokenType const& t)
{
	os << token2str(t);
	return os;
}

struct xac_hmac {
	uint8_t hmac[64];

};

struct subject {
	struct xac_hmac hmac;
	uint64_t canary;
};

struct object {
	uint64_t i_number;
	uint64_t st_dev;
	uint32_t i_gen;
	uint32_t canary;

};

struct verdict {
	uint32_t flags = 0;
};

struct subject_line {
	verdict v;
	uint32_t subid;
	uint32_t ruleid;
};

struct object_line {
	verdict v;
	uint32_t objid;
	uint32_t ruleid;
};

struct subject_record {
	uint32_t subid;
	std::vector<object_line> objs;
};

struct object_record {
	uint32_t objid;
	std::vector<subject_line> subs;
};

bool operator<(xac_hmac const& left,
					xac_hmac const &right) {
	for (int i = 0; i < 64; i++) {
		if (left.hmac[i] < right.hmac[i])
			return true;
		else if (left.hmac[i] > right.hmac[i])
			return false;
	}
	return false;
}

struct subject_compare {
	bool operator()(subject const &left,
				subject const &right) const {
		return left.hmac < right.hmac;
	}
};

struct object_compare {
	bool operator()(object const &left, object const &right) const {
		if (left.i_number < right.i_number)
			return true;
		else if (left.i_number > right.i_number)
			return false;

		if (left.st_dev < right.st_dev)
			return true;
		else if (left.st_dev > right.st_dev)
			return false;

		if (left.i_gen < right.i_gen)
			return true;
		else
			return false;
	}
};

using subjects_t = std::map<subject, uint32_t, subject_compare>;
using subjects_symtab_t = std::map<uint32_t, string>;
using subject_ids_t = std::map<uint32_t, subject>;

using objects_t = std::map<object, uint32_t, object_compare>;
using objects_symtab_t = std::map<uint32_t, string>;
using object_ids_t = std::map<uint32_t, object>;

struct rule_set {
	subjects_t subjects;
	objects_t objects;
	subjects_symtab_t subjects_symtab;
	objects_symtab_t objects_symtab;
	subject_ids_t subject_ids;
	object_ids_t object_ids;
	std::vector<subject_record> subject_records;
	std::vector<object_record> object_records;
};

std::ostream&
operator<<(std::ostream &os, xac_hmac const& h)
{
#ifdef PRINT_FULL_MAC
	for (uint8_t const b: h.hmac)
		os << std::hex << (uint32_t)b;
#else
	for (int i = 0; i < 4; i++)
		os << std::hex << (uint32_t)h.hmac[i];
#endif
	os << std::dec;
	return os;
}

std::ostream&
operator<<(std::ostream &os, subject const &s)
{
	os << s.hmac;
	return os;
}

std::ostream&
operator<<(std::ostream &os, object const &o)
{
	os << o.i_number;
	return os;
}

std::ostream&
operator<<(std::ostream &os, verdict const &v)
{
	if (v.flags & ALLOW)
		os << "+";
	else
		os << "-";
	if (v.flags & READ)
		os << "R";
	if (v.flags & WRITE)
		os << "W";
	if (v.flags & EXECUTE)
		os << "X";
	if (v.flags & LOG)
		os << " [L]";
	return os;
}

std::ostream&
operator<<(std::ostream &os, rule_set const& rs)
{
	auto tab = "  ";

	for (auto const &srec: rs.subject_records) {
		os << TokenType::SUB_TOKEN << " ";
		if (srec.subid == 0) {
			os << "* ";
		} else {
			auto t = rs.subject_ids.find(srec.subid);
			os << t->second << std::endl;
		}
		for (auto const &obj: srec.objs) {
			os << tab;
			os << obj.v << " ";
			if (obj.objid == 0) {
				os << "* ";
			} else {
				auto o = rs.object_ids.find(obj.objid);
				os << o->second << " ";
			}
			os << std::endl;
		}
	}

	for (auto const &orec: rs.object_records) {
		os << TokenType::OBJ_TOKEN << " ";
		if (orec.objid == 0) {
			os << "* ";
		} else {
			auto t = rs.object_ids.find(orec.objid);
			os << t->second << std::endl;
		}
		for (auto const &sub: orec.subs) {
			os << tab;
			os << sub.v << " ";
			if (sub.subid == 0) {
				os << "* ";
			} else {
				auto o = rs.subject_ids.find(sub.subid);
				os << o->second << " ";
			}
			os << std::endl;
		}
	}
	return os;
}

class ruleset_parser {
public:
	ruleset_parser(string const &path);

	shared_ptr<rule_set> get_ruleset();
	string dump();

private:
	const string FileNotFoundErrorMessage {"Rule file not found"};
	const string ParseAccessErrorMessage {"Invalid access specifier"};
	const string PathExpectedErrorMessage {"Invalid path specification"};
	const string InvalidPathErrorMessage {"Invalid path specification"};
	const string TabExpectedErrorMessage {"Tab character expected"};
	const string WhiteSpaceExpectedErrorMessage {"White space expected"};
	const string NewLineExpectedErrorMessage {"New line expected"};
	const string SubObjTypeSpecExpectedErrorMessage {
		"Expected "s + token2str(TokenType::SUB_TOKEN) +
		" or " + token2str(TokenType::OBJ_TOKEN) + " speciifer"
	};

	shared_ptr<rule_set> rs;

	bool s_access(string s);
	void skip_white_space(deque<token> &tokens);
	bool is_access(string s);
	token next_token(std::ifstream &f);
	deque<token> tokenize(string config_path);
	subject create_subject(string path);
	object create_object(string path);
	uint16_t parse_access(deque<token> &tokens);
	uint32_t parse_subject(deque<token> &tokens, subjects_t &subjects,
				subject_ids_t &subject_ids, subjects_symtab_t &subjects_symtab);
	uint32_t parse_object(deque<token> &tokens, objects_t &objects,
				object_ids_t &object_ids, objects_symtab_t &objects_symtab);
	subject_line
	parse_subject_line(deque<token> &tokens, subjects_t &subjects,
				subject_ids_t &subject_ids, subjects_symtab_t &subjects_symtab);
	object_line
	parse_object_line(deque<token> &tokens, objects_t &objects,
				object_ids_t &object_ids, objects_symtab_t &objects_symtab);
	subject_record
	parse_subject_record(deque<token> &tokens,
						 subjects_t &subjects,
						 subject_ids_t &subject_ids,
						 objects_t &objects,
						 object_ids_t &object_ids,
						 subjects_symtab_t &subjects_symtab,
						 objects_symtab_t &objects_symtab);
	object_record
	parse_object_record(deque<token> &tokens,
						 subjects_t &subjects,
						 subject_ids_t &subject_ids,
						 objects_t &objects,
						 object_ids_t &object_ids,
						 subjects_symtab_t &subjects_symtab,
						 objects_symtab_t &objects_symtab);

	friend std::ostream& operator<<(std::ostream &os, rule_set const& rs);
	friend std::ostream& operator<<(std::ostream &os, verdict const &v);
	friend std::ostream& operator<<(std::ostream &os, object const &o);
	friend std::ostream& operator<<(std::ostream &os, subject const &s);
	friend std::ostream& operator<<(std::ostream &os, xac_hmac const& h);
};

ruleset_parser::ruleset_parser(string const &config_path)
	: rs{new rule_set{}}
{
	deque<token> tokens = tokenize(config_path);
	skip_white_space(tokens);
	while (tokens.size() > 0) {
		if (tokens.front().type == TokenType::SUB_TOKEN) {
			auto srec = parse_subject_record(tokens, rs->subjects, rs->subject_ids,
												rs->objects, rs->object_ids,
												rs->subjects_symtab, rs->objects_symtab);
			rs->subject_records.push_back(srec);
		} else if (tokens.front().type == TokenType::OBJ_TOKEN) {
			auto orec = parse_object_record(tokens, rs->subjects, rs->subject_ids,
											rs->objects, rs->object_ids,
											rs->subjects_symtab, rs->objects_symtab);
			rs->object_records.push_back(orec);
		} else if (tokens.front().type == TokenType::EOF_TOKEN) {
			break;
		} else {
			throw config_error{tokens.front().line,
							SubObjTypeSpecExpectedErrorMessage};
		}
		skip_white_space(tokens);
	}
}

shared_ptr<rule_set>
ruleset_parser::get_ruleset()
{
	return rs;
}

bool
ruleset_parser::is_access(string s)
{
	size_t R = std::count(s.begin(), s.end(), 'R');
	size_t W = std::count(s.begin(), s.end(), 'W');
	size_t X = std::count(s.begin(), s.end(), 'X');
	size_t r = std::count(s.begin(), s.end(), 'r');
	size_t w = std::count(s.begin(), s.end(), 'w');
	size_t x = std::count(s.begin(), s.end(), 'x');

	if (R + W + X + r + w + x == s.size())
		return true;

	return false;
}

void
ruleset_parser::skip_white_space(deque<token> &tokens)
{
	while (tokens.front().type == TokenType::NEW_LINE ||
			tokens.front().type == TokenType::TAB ||
			tokens.front().type == TokenType::WS)
		tokens.pop_front();
}

token
ruleset_parser::next_token(std::ifstream &f)
{
	string str;
	char c;
	token t;
	static int32_t line = 1;

	f >> std::noskipws;
	while (f >> c) {
		if (c == ' ' || c == '\n' || c == '\t') {
			if (str.size() > 0) {
				if (str == "*") {
					t.type = TokenType::ASTERISK;
					t.val = str;
				} else if (str == "!") {
					t.type = TokenType::INVERT;
					t.val = str;
				} else if (str[0] == '/') {
					t.type = TokenType::PATH;
					t.val = str;
				} else if (str.size() <= 3 && is_access(str)) {
					t.type = TokenType::ACCESS;
					t.val = str;
				} else if (str == token2str(TokenType::SUB_TOKEN)) {
					t.type = TokenType::SUB_TOKEN;
					t.val = str;
				} else if (str == token2str(TokenType::OBJ_TOKEN)) {
					t.type = TokenType::OBJ_TOKEN;
					t.val = str;
				} else if (str == token2str(TokenType::LOG_TOKEN)) {
					t.type = TokenType::LOG_TOKEN;
					t.val = str;
				} else {
					t.type = TokenType::BAD_TOKEN;
					t.val = str;
				}
				f.putback(c);
				break;
			} else {
				if (c == ' ') {
					t.type = TokenType::WS;
					t.val = c;
					break;
				}
				if (c == '\n') {
					t.type = TokenType::NEW_LINE;
					t.val = c;
					line++;
					break;
				}
				if (c == '\t') {
					t.type = TokenType::TAB;
					t.val = c;
					break;
				}
				t.type = TokenType::BAD_TOKEN;
				t.val = str;
			}
		}
		str.push_back(c);
	}
	if (f.eof())
		t.type = TokenType::EOF_TOKEN;
	t.line = line;
	return t;
}

deque<token>
ruleset_parser::tokenize(string config_path)
{
	deque<token> tokens;
	std::ifstream f {config_path};

	if (!f.good()) {
		throw config_error{FileNotFoundErrorMessage};
	}

	while (1) {
		token t = next_token(f);
		tokens.push_back(t);
		if (f.eof())
			break;
	}
	return tokens;
}

subject
ruleset_parser::create_subject(string path)
{
	subject s;
	try {
		auto digest = digest_file(path);
		memcpy(s.hmac.hmac, digest.get(), 64);
		s.canary = kSPCanary;
	} catch (...) {
		throw config_error{InvalidPathErrorMessage};
	}
	return (s);
}

object
ruleset_parser::create_object(string path)
{
	object o;
	try {
		get_file_stat(path, o.i_number, o.st_dev, o.i_gen);
		o.canary = kOPCanary;
	} catch (...) {
		throw config_error{InvalidPathErrorMessage};
	}
	return (o);
}

/**
 * Parse a string of format [R][W][X] in that order.
 */
uint16_t
ruleset_parser::parse_access(deque<token> &tokens)
{
	enum { ON = 0xff, OFF = 0x00 };
	uint16_t r = OFF, w = OFF, x = OFF;
	uint16_t access_spec = 0;

	auto token = tokens.front();
	tokens.pop_front();
	string access = token.val;

	switch (access.size()) {
	case 3:
		if (access[2] == 'X')
			x = ON;
		else
			throw config_error{token.line, ParseAccessErrorMessage};

		/* FALLTHROUGH */
	case 2:
		if (access[1] == 'W')
			w = ON;
		else if (access[1] == 'X') {
			if (x)
				throw config_error{token.line, ParseAccessErrorMessage};
			else
				x = ON;
		} else
			throw config_error{token.line, ParseAccessErrorMessage};

		/* FALLTHROUGH */
	case 1:
		if (access[0] == 'R')
			r = ON;
		else if (access[0] == 'W') {
			if (w)
				throw config_error{token.line, ParseAccessErrorMessage};
			else
				w = ON;
		} else if (access[0] == 'X') {
			if (x)
				throw config_error{token.line, ParseAccessErrorMessage};
			else
				x = OFF;
		}
		break;

	case 0:
		throw config_error{token.line, ParseAccessErrorMessage};
	}

	access_spec |= (r & READ) |
					(w & WRITE) |
					(x & EXECUTE);
	return access_spec;
}

uint32_t
ruleset_parser::parse_subject(deque<token> &tokens, subjects_t &subjects,
				subject_ids_t &subject_ids, subjects_symtab_t &subjects_symtab)
{
	subject sub;
	uint32_t ind;
	token token;

	if (tokens.front().type == TokenType::PATH) {
		token = tokens.front();
		tokens.pop_front();
		try {
			sub = create_subject(token.val);
		} catch (config_error &pe) {
			pe.set_line(token.line);
			throw;
		}
		auto ps = subjects.find(sub);
		if (ps == subjects.end()) {
			ind = subjects.size() + 1;
			subjects.insert(std::pair<subject, uint32_t>{sub, ind});
			subjects_symtab.insert(std::pair<uint32_t, std::string>{ind, token.val});
			subject_ids.insert(std::pair<uint32_t, subject>{ind, sub});
		} else {
			ind = ps->second;
		}
	} else
		throw config_error{token.line, PathExpectedErrorMessage};

	return (ind);
}

uint32_t
ruleset_parser::parse_object(deque<token> &tokens, objects_t &objects,
			object_ids_t &object_ids, objects_symtab_t &objects_symtab)
{
	object obj;
	uint32_t ind;

	if (tokens.front().type == TokenType::PATH) {
		auto token = tokens.front();
		tokens.pop_front();
		try {
			obj = create_object(token.val);
		} catch (config_error &pe) {
			pe.set_line(token.line);
			throw;
		}
		auto po = objects.find(obj);
		if (po == objects.end()) {
			ind = objects.size() + 1;
			objects.insert(std::pair<object, uint32_t>{obj, ind});
			objects_symtab.insert(std::pair<uint32_t, std::string>{ind, token.val});
			object_ids.insert(std::pair<uint32_t, object>{ind, obj});
		} else {
			ind = po->second;
		}
	} else
		throw config_error{tokens.front().line, PathExpectedErrorMessage};

	return (ind);
}

subject_line
ruleset_parser::parse_subject_line(deque<token> &tokens, subjects_t &subjects,
					subject_ids_t &subject_ids, subjects_symtab_t &subjects_symtab)
{
	subject_line sl;
	
	sl.ruleid = tokens.front().line;

	if (tokens.front().type == TokenType::TAB) {
		tokens.pop_front();
	} else
		throw config_error{tokens.front().line, TabExpectedErrorMessage};

	if (tokens.front().type == TokenType::INVERT) {
		sl.v.flags &= !ALLOW;
		tokens.pop_front();
		if (tokens.front().type == TokenType::WS) {
			tokens.pop_front();
		} else {
			throw config_error{tokens.front().line, WhiteSpaceExpectedErrorMessage};
		}
	} else {
		sl.v.flags |= ALLOW;
	}

	if (tokens.front().type == TokenType::ASTERISK) {
		tokens.pop_front();
		sl.subid = 0;
	} else if (tokens.front().type == TokenType::PATH) {
		sl.subid = parse_subject(tokens, subjects, subject_ids, subjects_symtab);
	} else {
		throw config_error{tokens.front().line, PathExpectedErrorMessage};
	}

	if (tokens.front().type == TokenType::WS) {
		tokens.pop_front();
	} else {
		throw config_error{tokens.front().line, WhiteSpaceExpectedErrorMessage};
	}

	if (tokens.front().type == TokenType::ACCESS) {
		sl.v.flags |= parse_access(tokens);
	} else {
		throw config_error{tokens.front().line, ParseAccessErrorMessage};
	}

	if (tokens.front().type == TokenType::WS) {
		tokens.pop_front();
		if (tokens.front().type == TokenType::LOG_TOKEN) {
			sl.v.flags |= LOG;
			tokens.pop_front();
		}
	}

	if (tokens.front().type == TokenType::NEW_LINE) {
		tokens.pop_front();
	} else {
		throw config_error{tokens.front().line, ParseAccessErrorMessage};
	}

	return (sl);
}

object_line
ruleset_parser::parse_object_line(deque<token> &tokens, objects_t &objects,
					object_ids_t &object_ids, objects_symtab_t &objects_symtab)
{
	object_line ol;
	
	ol.ruleid = tokens.front().line;

	if (tokens.front().type == TokenType::TAB) {
		tokens.pop_front();
	} else
		throw config_error{tokens.front().line, TabExpectedErrorMessage};

	if (tokens.front().type == TokenType::INVERT) {
		ol.v.flags &= !ALLOW;
		tokens.pop_front();
		if (tokens.front().type == TokenType::WS) {
			tokens.pop_front();
		} else {
			throw config_error{tokens.front().line, WhiteSpaceExpectedErrorMessage};
		}
	} else {
		ol.v.flags |= ALLOW;
	}

	if (tokens.front().type == TokenType::ASTERISK) {
		tokens.pop_front();
		ol.objid = 0;
	} else if (tokens.front().type == TokenType::PATH) {
		ol.objid = parse_object(tokens, objects, object_ids, objects_symtab);
	} else {
		throw config_error{tokens.front().line, PathExpectedErrorMessage};
	}

	if (tokens.front().type == TokenType::WS) {
		tokens.pop_front();
	} else {
		throw config_error{tokens.front().line, WhiteSpaceExpectedErrorMessage};
	}

	if (tokens.front().type == TokenType::ACCESS) {
		ol.v.flags |= parse_access(tokens);
	} else {
		throw config_error{tokens.front().line, ParseAccessErrorMessage};
	}

	if (tokens.front().type == TokenType::WS) {
		tokens.pop_front();
		if (tokens.front().type == TokenType::LOG_TOKEN) {
			ol.v.flags |= LOG;
			tokens.pop_front();
		}
	}
	if (tokens.front().type == TokenType::NEW_LINE) {
		tokens.pop_front();
	} else {
		throw config_error{tokens.front().line, ParseAccessErrorMessage};
	}

	return (ol);
}

subject_record
ruleset_parser::parse_subject_record(deque<token> &tokens,
					 subjects_t &subjects,
					 subject_ids_t &subject_ids,
					 objects_t &objects,
					 object_ids_t &object_ids,
					 subjects_symtab_t &subjects_symtab,
					 objects_symtab_t &objects_symtab)
{
	subject_record srec;

	tokens.pop_front(); // pop the TYPE token
	if (tokens.front().type != TokenType::WS)
		throw config_error{tokens.front().line, WhiteSpaceExpectedErrorMessage};
	tokens.pop_front();
	srec.subid = parse_subject(tokens, subjects, subject_ids, subjects_symtab);

	if (tokens.front().type != TokenType::NEW_LINE)
		throw config_error{tokens.front().line, NewLineExpectedErrorMessage};
	tokens.pop_front();

	do {
		auto object_line = parse_object_line(tokens, objects, object_ids, objects_symtab);
		srec.objs.push_back(object_line);
	} while (tokens.front().type != TokenType::NEW_LINE);

	return srec;
}

object_record
ruleset_parser::parse_object_record(deque<token> &tokens,
					 subjects_t &subjects,
					 subject_ids_t &subject_ids,
					 objects_t &objects,
					 object_ids_t &object_ids,
					subjects_symtab_t &subjects_symtab,
					objects_symtab_t &objects_symtab)
{
	object_record orec;

	tokens.pop_front(); // pop the TYPE token
	if (tokens.front().type != TokenType::WS)
		throw config_error{tokens.front().line, WhiteSpaceExpectedErrorMessage};
	tokens.pop_front();
	orec.objid = parse_object(tokens, objects, object_ids, objects_symtab);

	if (tokens.front().type != TokenType::NEW_LINE)
		throw config_error{tokens.front().line, NewLineExpectedErrorMessage};
	tokens.pop_front();

	do {
		auto subject_line = parse_subject_line(tokens, subjects, subject_ids, subjects_symtab);
		orec.subs.push_back(subject_line);
	} while (tokens.front().type != TokenType::NEW_LINE);

	return orec;
}

string
ruleset_parser::dump()
{
	std::ostringstream os;
	os << *rs;
	return os.str();
}

class ruleset_serializer {
public:
	ruleset_serializer(shared_ptr<rule_set> rs);

	shared_ptr<vector<uint8_t>> get_serbuf();
	shared_ptr<vector<uint8_t>> get_symtabbuf();
	
private:
	shared_ptr<vector<uint8_t>> servec;
	shared_ptr<vector<uint8_t>> symtab;

	void append_bytes(uint8_t const *bs, uint32_t len,
						shared_ptr<vector<uint8_t>> blob);
	template<typename T>
	void append(T d, shared_ptr<vector<uint8_t>> blob);
	void append(string s, shared_ptr<vector<uint8_t>> blob);
	template<typename T, uint32_t N>
	void append(T (&arr)[N], shared_ptr<vector<uint8_t>> blob);
	template<typename T>
	void append_rs(T d);
	template<typename T, uint32_t N>
	void append_rs(T (&arr)[N]);
	template<typename T>
	void append_symtab(T d);
	template<typename T, uint32_t N>
	void append_symtab(T (&arr)[N]);
};

/**
 * All data in output buffer are properly aligned.
 */
ruleset_serializer::ruleset_serializer(shared_ptr<rule_set> rs)
	: servec{new vector<uint8_t>},
	symtab{new vector<uint8_t>}
{
	uint64_t rules_cnt = 0;
	for (auto const &srec: rs->subject_records)
		for (auto const &objl: srec.objs)
			rules_cnt++;
	for (auto const &orec: rs->object_records)
		for (auto const &subl: orec.subs)
			rules_cnt++;

	append_symtab((uint32_t)rs->subject_ids.size());
	append_symtab((uint32_t)rs->object_ids.size());

	append_rs((uint32_t)rs->subject_ids.size());
	append_rs((uint32_t)rs->object_ids.size());
	append_rs((uint32_t)rules_cnt);

	for (int i = 0; i < rs->subject_ids.size(); i++) {
		auto sub = rs->subject_ids.find(i + 1)->second;
		auto path = rs->subjects_symtab.find(i + 1)->second;
		append_rs(sub);
		append_symtab(sub);
		append_symtab(path);
	}

	for (int i = 0; i < rs->object_ids.size(); i++) {
		auto obj = rs->object_ids.find(i + 1)->second;
		auto path = rs->subjects_symtab.find(i + 1)->second;
		append_rs(obj);
		append_symtab(obj);
		append_symtab(path);
	}

	append_rs((uint32_t)rs->subject_records.size());
	for (auto const &srec: rs->subject_records) {
		append_rs(XAC_SUBJECT);
		append_rs(srec.subid);
		append_rs((uint32_t)srec.objs.size());
		for (auto const &objl: srec.objs) {
			append_rs(objl.ruleid);
			append_rs(objl.v.flags);
			append_rs(objl.objid);
		}
	}

	append_rs((uint32_t)rs->object_records.size());
	for (auto const &orec: rs->object_records) {
		append_rs(XAC_OBJECT);
		append_rs(orec.objid);
		append_rs((uint32_t)orec.subs.size());
		for (auto const &subl: orec.subs) {
			append_rs(subl.ruleid);
			append_rs(subl.v.flags);
			append_rs(subl.subid);
		}
	}
}

shared_ptr<vector<uint8_t>>
ruleset_serializer::get_serbuf()
{
	return servec;
}

shared_ptr<vector<uint8_t>>
ruleset_serializer::get_symtabbuf()
{
	return symtab;
}

void
ruleset_serializer::append_bytes(uint8_t const *bs, uint32_t len, shared_ptr<vector<uint8_t>> blob)
{
	blob->insert(blob->end(), bs, bs + len);
}

void
ruleset_serializer::append(string s, shared_ptr<vector<uint8_t>> blob)
{
	append_bytes(reinterpret_cast<uint8_t const*>(s.c_str()), strlen(s.c_str()) + 1, blob);
}

template<typename T>
void
ruleset_serializer::append(T d, shared_ptr<vector<uint8_t>> blob)
{
	append_bytes(reinterpret_cast<uint8_t*>(&d), sizeof(T), blob);
}

template<typename T, uint32_t N>
void
ruleset_serializer::append(T (&arr)[N], shared_ptr<vector<uint8_t>> blob)
{
	for (uint32_t i = 0; i < N; i++) {
		append_bytes(reinterpret_cast<uint8_t*>(&arr[i]), sizeof(T), blob);
	}
}

template<typename T>
void
ruleset_serializer::append_rs(T d)
{
	append(d, servec);
}

template<typename T, uint32_t N>
void
ruleset_serializer::append_rs(T (&arr)[N])
{
	append(arr, servec);
}

template<typename T>
void
ruleset_serializer::append_symtab(T d)
{
	append(d, symtab);
}

template<typename T, uint32_t N>
void
ruleset_serializer::append_symtab(T (&arr)[N])
{
	append(arr, symtab);
}

} // anonymous namespace

/**
 * Loads and verifies XAC ruleset contained in 'path'
 * and returns ruleset binary blob and symbol table.
 */
std::tuple<shared_ptr<vector<uint8_t>>, shared_ptr<vector<uint8_t>>>
compile_ruleset(string path, bool dump)
{
	auto rp = ruleset_parser{path};
	auto rs = rp.get_ruleset();
	if (dump)
		std::cout << rp.dump() << std::endl;
	ruleset_serializer rss{rs};
	return std::make_tuple(rss.get_serbuf(), rss.get_symtabbuf());
}

static void
_ruleset_configure(std::string path, bool parse_only)
{
	std::cout << "loading XAC ruleset from " << path << std::endl;
	auto ruleset = compile_ruleset(path, false);
	if (!parse_only) {
		std::ofstream bf{XAC_CONF_PATH};
		std::ofstream bf_symtab{XAC_SYMTAB_PATH};
		for (uint8_t const b: *std::get<0>(ruleset))
			bf << b;
		for (uint8_t const b: *std::get<1>(ruleset))
			bf_symtab << b;
		bf.flush();
		bf.close();
	}

	if (parse_only)
		std::cout << "warning: ruleset binary was not written to disk."
					<< std::endl;
	else
		std::cout << "ruleset binary updated." << std::endl;
}

void
ruleset_configure(std::string path)
{
	_ruleset_configure(path, false);
}

void
ruleset_configure_nc(std::string path)
{
	_ruleset_configure(path, true);
}
