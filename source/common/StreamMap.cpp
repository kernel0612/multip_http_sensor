/*
 * StreamMap.cpp
 *
 *  Created on: 2014Äê7ÔÂ25ÈÕ
 *      Author: Administrator
 */

#include "StreamMap.h"

StreamMap::StreamMap() {
	// TODO Auto-generated constructor stub

}

StreamMap::~StreamMap() {
	// TODO Auto-generated destructor stub
	this->destroy();
}

int StreamMap::create(const char* ip,unsigned short port){

	_client=ssdb::Client::connect(ip,port);
	if(_client==0){
		return -1;
	}
	return 0;
}

Stream *StreamMap::find( StreamKey &key){
	if(_client==0){
		return 0;
	}
	if(!serialization_StreamKey_to_protobuf(key)){
		return 0;
	}
	ssdb::Status s;
	s=_client->get(_strkey,&_strstream);
	if(s.ok()){
		if(!get_Stream_from_protobuf()){
			return 0;
		}
		return &_stream;
	}
	return 0;
}


int StreamMap::insert( StreamKey &key,  Stream &t){
	if(_client==0){
		return -1;
	}
	if(!serialization_StreamKey_to_protobuf(key)
			||!serialization_Stream_to_protobuf(t)){
		return -1;
	}
	ssdb::Status s;
	s=_client->set(_strkey,_strstream);
	if(s.ok()){
		return 0;
	}
	return -1;
}


int StreamMap::erase(StreamKey &key){
	if(_client==0){
		return 0;
	}
	if(!serialization_StreamKey_to_protobuf(key)){
		return -1;
	}
	ssdb::Status s;
	s=_client->del(_strkey);
	if(s.ok()){
		return 0;
	}
	return -1;
}


int StreamMap::destroy(){
	if(_client){
		delete _client;
		_client=0;
	}
	return 0;
}


void StreamMap::dump(ostream &os) const{

}

int StreamMap::serialization_StreamKey_to_protobuf(StreamKey& key){
	StreamPackage::StreamKey proto_key;
	proto_key.set_saddr(key.saddr);
	proto_key.set_daddr(key.daddr);
	proto_key.set_sport(key.sport);
	proto_key.set_dport(key.dport);
	if(!proto_key.SerializeToString(&_strkey)){
		//
		return -1;
	}
	return 0;
}
int StreamMap::serialization_Stream_to_protobuf(Stream& t){


	StreamPackage::StreamKey proto_key;
	proto_key.set_saddr(t.key.saddr);
	proto_key.set_daddr(t.key.daddr);
	proto_key.set_sport(t.key.sport);
	proto_key.set_dport(t.key.dport);

	StreamPackage::timeval  proto_timeval;
	proto_timeval.set_tv_sec(t.begin.tv_sec);
	proto_timeval.set_tv_usec(t.begin.tv_usec);

	StreamPackage::Stream  proto_stream;
	proto_stream.set_allocated_key(&proto_key);
	proto_stream.add_mac((const void*)t.mac,12);//or   add_mac((const char*)t.mac)

	proto_stream.set_allocated_begin(&proto_timeval);   //ok
	proto_stream.set_live(t.live);
	proto_stream.set_service(t.service);
	proto_stream.set_seq(t.seq);
	proto_stream.set_ack_seq(t.ack_seq);
	proto_stream.set_stat(t.stat);
	proto_stream.set_flag(t.flag);
	proto_stream.set_sid(t.sid);
	proto_stream.set_devid(t.devid);
	proto_stream.set_rid(t.rid);
	proto_stream.add_account((const void*)t.account,32);

    proto_stream.set_bytes(t.bytes);
    proto_stream.set_packets(t.packets);
    proto_stream.set_records(t.records);
	proto_stream.add_client((const void*)t.client,128);  //
	proto_stream.add_server((const void*)t.server,128);  //
	proto_stream.add_response((const void*)t.response,1536);  //
    proto_stream.add_private_data((const void*)t.private_data
    		,strlen(t.private_data));   //

    StreamPackage::timeval  proto_ORM_timval;
    proto_ORM_timval.set_tv_sec(t.trans.ts.tv_sec);
    proto_ORM_timval.set_tv_usec(t.trans.ts.tv_usec);

    StreamPackage::ORMTransaction  proto_trans;
    proto_trans.set_sid(t.trans.sid);
    proto_trans.set_allocated_ts(&proto_ORM_timval);
    proto_trans.add_account((const void*)t.trans.account,32);   //

    proto_trans.set_sip(t.trans.sip);
    proto_trans.set_dip(t.trans.dip);
    proto_trans.set_sport(t.trans.sport);
    proto_trans.set_dport(t.trans.dport);
    proto_trans.set_protocol(t.trans.protocol);
    proto_trans.set_tcp_seq(t.trans.tcp_seq);
    proto_trans.set_tcp_ack_seq(t.trans.tcp_ack_seq);
    proto_trans.set_drt((StreamPackage::ORMTransaction_direct)t.trans.direct);             //
    proto_trans.set_seq(t.trans.seq);
    proto_trans.set_duration(t.trans.duration);
    proto_trans.set_data_len(t.trans.data_len);
	proto_trans.add_operate((const void*)t.trans.operate,64);   //
	proto_trans.add_object((const void*)t.trans.object,64);     //
	proto_trans.add_result((const void*)t.trans.result,64);     //
	proto_trans.add_data((const void*)t.trans.data,1536);     //

    proto_stream.set_allocated_trans(&proto_trans);
	if(!proto_stream.SerializeToString(&_strstream)){
		//
		return -1;
	}
	return 0;
}
int StreamMap::get_StreamKey_from_protobuf(){
     StreamPackage::StreamKey  key;
     if(!key.ParseFromString(_strkey)){
    	 return -1;
     }
     //
     _key.saddr=key.saddr();
     _key.daddr=key.daddr();
     _key.sport=key.sport();
     _key.dport=key.dport();
     return 0;

}
int StreamMap::get_Stream_from_protobuf(){
    StreamPackage::Stream  stream;
     if(!stream.ParseFromString(_strstream)){
    	 return -1;
     }
     _stream.key.saddr=stream.key().saddr();    //?
     _stream.key.daddr=stream.key().daddr();    //?
     _stream.key.sport=stream.key().sport();    //?
     _stream.key.dport=stream.key().dport();    //?

     memcpy(_stream.mac,stream.mac(0).c_str(),12);
     _stream.begin.tv_sec=stream.begin().tv_sec();
     _stream.begin.tv_usec=stream.begin().tv_usec();
     _stream.live=stream.live();
     _stream.service=stream.service();
     _stream.seq=stream.seq();
     _stream.ack_seq=stream.ack_seq();
     _stream.stat=stream.stat();
     _stream.flag=stream.flag();
     _stream.sid=stream.sid();
     _stream.devid=stream.devid();
     _stream.rid=stream.rid();
     memcpy(_stream.account,stream.account(0).c_str(),32);

     _stream.bytes=stream.bytes();
     _stream.packets=stream.packets();
     _stream.records=stream.records();
     memcpy(_stream.client,stream.client(0).c_str(),128);
     memcpy(_stream.server,stream.server(0).c_str(),128);
     memcpy(_stream.response,stream.response(0).c_str(),1536);
     memcpy(_stream.private_data,stream.private_data(0).c_str()
    		 ,stream.private_data(0).length());

     _stream.trans.sid=stream.trans().sid();
     _stream.trans.ts.tv_sec=stream.trans().ts().tv_sec();
     _stream.trans.ts.tv_usec=stream.trans().ts().tv_usec();
     memcpy(_stream.trans.account,stream.trans().account(0).c_str(),32);
     _stream.trans.sip=stream.trans().sip();
     _stream.trans.dip=stream.trans().dip();
     _stream.trans.sport=stream.trans().sport();
     _stream.trans.dport=stream.trans().dport();
     _stream.trans.protocol=stream.trans().protocol();
     _stream.trans.service=stream.trans().service();
     _stream.trans.tcp_ack_seq=stream.trans().tcp_ack_seq();
     _stream.trans.tcp_seq=stream.trans().tcp_seq();
     _stream.trans.direct=(short)stream.trans().drt();
     _stream.trans.seq=stream.trans().seq();
     _stream.trans.duration=stream.trans().duration();
     _stream.trans.data_len=stream.trans().data_len();
     memcpy(_stream.trans.operate,stream.trans().operate(0).c_str(),64);
     memcpy(_stream.trans.object,stream.trans().object(0).c_str(),64);
     memcpy(_stream.trans.result,stream.trans().result(0).c_str(),64);
     memcpy(_stream.trans.data,stream.trans().data(0).c_str(),1536);
     return 0;
}
