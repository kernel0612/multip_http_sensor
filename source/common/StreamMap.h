/*
 * StreamMap.h
 *
 *  Created on: 2014Äê7ÔÂ25ÈÕ
 *      Author: Administrator
 */

#ifndef STREAMMAP_H_
#define STREAMMAP_H_
#include<iostream>
#include<fstream>
#include<string>
#include "SSDB.h"
#include "Stream.pb.h"
#include "Stream.h"
using namespace std;

class StreamMap {
public:
	StreamMap();
	virtual ~StreamMap();
	//! create map object.
	int create(const char* ip,unsigned short port);

	//! Search key in table.
	Stream *find( StreamKey &key);

	//! Insert key into map.
	int insert( StreamKey &key,  Stream &t);

	//! Erase key from map.
	int erase(StreamKey &key);

	//! destroy map object.
	int destroy();

	//! dump information.
    void dump(ostream &os) const;

private:
    int serialization_StreamKey_to_protobuf(StreamKey& key);
    int serialization_Stream_to_protobuf(Stream& t);
    int get_StreamKey_from_protobuf();
    int get_Stream_from_protobuf();

    string _strkey;
    string _strstream;
    StreamKey _key;
    Stream  _stream;
    ssdb::Client* _client;
};

#endif /* STREAMMAP_H_ */
