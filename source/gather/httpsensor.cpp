/*
 * httpsensor.cpp
 *
 *  Created on: 2014Äê7ÔÂ18ÈÕ
 *      Author: Administrator
 */

#include "httpsensor.h"

http_sensor::http_sensor():
classifier_(NULL), stream_dispatcher_(NULL), outputer_(NULL),
buffer_size_(DEFAULT_BUFFER), max_stream_(DEFAULT_STREAM),
stream_timeout_(StreamAuditor::STREAM_TIMEOUT), device_id_(0),
ni_num_(0){
	// TODO Auto-generated constructor stub
   // _captor=0;
   // _auditor=0;
   // _outputor=0;
   // _logger=0;
   // _capted_fifo=0;
   // _output_fifo=0;

	  memset(captor_, 0, sizeof(captor_));
	  //  memset(stream_auditor_, 0, sizeof(stream_auditor_));
	  memset(config_file_, 0, sizeof(config_file_));
	  strncpy(log_file_, GATHER_DEFAULT_LOG, sizeof(log_file_));
	  memset(prefix_, 0, sizeof(prefix_));
	  memset(gather_file_, 0, sizeof(gather_file_));
	  memset(nis_, 0, sizeof(nis_));
	  strncpy(
	    filter_,
	    "(tcp[13] & 0x07 != 0) or (ip[2:2] - ((ip[0] & 0x0f) * 4) - ((tcp[12] & 0xf0) / 4) > 0) or vlan",
	    sizeof(filter_));
	  time(&startup_);
}

http_sensor::~http_sensor() {
	// TODO Auto-generated destructor stub
	this->destroy();
}


int http_sensor::create(){

	int ret = 0;

	  // Load config file.
	//  if ((ret = read_config()) < 0) {
	//    ACE_DEBUG((LM_ERROR, " Gather: load failed: %s, return %d. Make sure set the config file name correctly.\n", config_file_, ret));
	//    return -1;
	//  }

	  // Set log file.
	#ifdef DEBUG
	  outlog_.open(log_file_, std::ios::out | std::ios::trunc);
	#else
	  outlog_.open(log_file_, std::ios::out | std::ios::app);
	#endif

	  if (!outlog_.is_open()) {
	    ACE_DEBUG((LM_ERROR, " Gather: Open log file failed: %s, return %d. Make sure can write the log file name.\n", log_file_, ret));
	    return -1;
	  }

	  ACE_LOG_MSG->msg_ostream(&this->outlog_, 1);
	  ACE_LOG_MSG->set_flags(ACE_Log_Msg::OSTREAM | ACE_Log_Msg::VERBOSE_LITE);
	  ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR);
	#ifndef DEBUG
	  ACE_LOG_MSG->priority_mask(
	    LM_INFO | LM_NOTICE | LM_WARNING | LM_ERROR | LM_CRITICAL | LM_ALERT
	    | LM_EMERGENCY, ACE_Log_Msg::PROCESS);
	#else
	  ACE_LOG_MSG->priority_mask(LM_TRACE | LM_DEBUG | LM_INFO | LM_NOTICE | LM_WARNING | LM_ERROR | LM_CRITICAL | LM_ALERT | LM_EMERGENCY, ACE_Log_Msg::PROCESS);
	#endif
	  ACE_LOG_MSG->open("gather", ACE_Log_Msg::OSTREAM, "NETGATHER_LOG");
	//  eventHandle_ = (GatherEventHandle *) operator new(sizeof(GatherEventHandle));
	  ACE_DEBUG((LM_DEBUG, " Audit: new eventHandle_.\n"));

	//  try {
	//    new(eventHandle_) GatherEventHandle(*this);
	//  } catch (...) {
	//    operator delete(eventHandle_);
	//    eventHandle_ = NULL;
	//    ACE_DEBUG((LM_ERROR, " Audit: new CLI failed.\n"));
	//    throw;
	//    return -1;
	//  }

	//  eventHandle_->reactor(ACE_Reactor::instance());

	//  if ((ret = eventHandle_->open()) < 0) {
	//    ACE_DEBUG((LM_ERROR, " Audit: create command interface event Handle failed: %d\n", ret));
	 //   return -1;
	//  }

	  /*
	   * Create classifier.
	   */
	  classifier_ = (GatherClassifier *) operator new(sizeof(GatherClassifier));
	  ACE_DEBUG((LM_DEBUG, " Audit: new GatherClassifier.\n"));

	  try {
	    new(classifier_) GatherClassifier(buffer_size_);
	  } catch (...) {
	    operator delete(classifier_);
	    classifier_ = NULL;
	    ACE_DEBUG((LM_ERROR, " Gather: new classifier failed.\n"));
	    throw;
	    return -1;
	  }

	  classifier_->device_id = device_id_;

	  if ((ret = classifier_->create()) < 0) {
	    ACE_DEBUG((LM_ERROR, " Gather: create classifier failed: %d\n", ret));
	    return -1;
	  }

	  /*
	   * Create more to 16 captores.
	   */
	  ACE_DEBUG((LM_DEBUG, " Audit: new 16 captor_.\n"));

	  for (int i = 0; i < ni_num_; i++) {
	    captor_[i] = (Captor<GatherClassifier> *) operator new(
	                   sizeof(Captor<GatherClassifier>));

	    try {
	      new(captor_[i]) Captor<GatherClassifier>(*classifier_);
	    } catch (...) {
	      operator delete(captor_[i]);
	      captor_[i] = NULL;
	      ACE_DEBUG((LM_ERROR, " Gather: new captor %d failed: %d\n", i, ret));
	      throw;
	      return -1;
	    }

	    captor_[i]->interface(nis_[i]);
	    captor_[i]->filter(filter_);

	    if ((ret = captor_[i]->create()) < 0) {
	      ACE_DEBUG((LM_ERROR, " Gather: create captor %d failed: %d. Maybe the interface is invalid.\n", i, ret));
	      operator delete(captor_[i]);
	      captor_[i] = NULL;
	      return -1;
	    } else {
	      ACE_DEBUG((LM_DEBUG, " Gather: create captor %d succeed: %d. Maybe the interface is invalid.\n", i, ret));
	    }
	  }

	  /*
	   * Create stream dispatcher.
	   */
	  stream_dispatcher_ = (StreamDispatcher *) operator new(
	                         sizeof(StreamDispatcher));

	  try {
	    new(stream_dispatcher_) StreamDispatcher(*classifier_);
	  } catch (...) {
	    operator delete(stream_dispatcher_);
	    stream_dispatcher_ = NULL;
	    ACE_DEBUG((LM_ERROR, " Gather: new stream dispatcher failed.\n"));
	    throw;
	    return -1;
	  }

	  stream_dispatcher_->policy().rule_file(gather_file_);

	  if ((ret = stream_dispatcher_->create()) < 0) {
	    ACE_DEBUG((LM_ERROR, " Gather: create stream dispatcher failed: %d\n", ret));
	    return -1;
	  }

	  /*
	   * Create stream auditors.
	   */
	  stream_auditor_ = (StreamAuditor *) operator new(sizeof(StreamAuditor));

	  try {
	    new(stream_auditor_) StreamAuditor(*classifier_, *stream_dispatcher_);
	  } catch (...) {
	    operator delete(stream_auditor_);
	    stream_auditor_ = NULL;
	    ACE_DEBUG((LM_ERROR, " Gather: new stream auditor failed.\n"));
	    throw;
	    return -1;
	  }

	  stream_auditor_->max_stream(max_stream_);
	  stream_auditor_->stream_timeout(stream_timeout_);

	  if ((ret = stream_auditor_->create()) < 0) {
	    ACE_DEBUG((LM_ERROR, " Gather: create stream auditor failed: %d\n", ret));
	    return -1;
	  }

	  /*
	   * Create audit outputer.
	   */
	  outputer_ = (GatherOutputer *) operator new(sizeof(GatherOutputer));

	  try {
	    new(outputer_) GatherOutputer(*classifier_);
	  } catch (...) {
	    operator delete(outputer_);
	    outputer_ = NULL;
	    ACE_DEBUG((LM_ERROR, " Gather: new outputer failed.\n"));
	    throw;
	    return -1;
	  }

	  if ((ret = outputer_->create()) < 0) {
	    ACE_DEBUG((LM_ERROR, " Gather: create outputer failed: %d\n", ret));
	    return -1;
	  }

	  return 0;
}
int http_sensor::destroy(){

	  if (outputer_ != NULL) {
	    outputer_->destroy();
	    delete outputer_;
	    outputer_ = NULL;
	  }

	  if (stream_auditor_ != NULL) {
	    stream_auditor_->destroy();
	    delete stream_auditor_;
	    stream_auditor_ = NULL;
	  }

	  if (stream_dispatcher_ != NULL) {
	    stream_dispatcher_->destroy();
	    delete stream_dispatcher_;
	    stream_dispatcher_ = NULL;
	  }

	  for (int i = 0; i < ni_num_; i++) {
	    if (captor_[i] != NULL) {
	      captor_[i]->destroy();
	      delete captor_[i];
	      captor_[i] = NULL;
	    }
	  }

	  if (classifier_ != NULL) {
	    classifier_->destroy();
	    delete classifier_;
	    classifier_ = NULL;
	  }

	//  if (eventHandle_ != NULL) {
	//    eventHandle_->close();
	//    delete eventHandle_;
	//    eventHandle_ = NULL;
	//  }

	  ACE_LOG_MSG->clr_flags(ACE_Log_Msg::MSG_CALLBACK);
	  outlog_.close();
	  return 0;
}
int http_sensor::run(){

    ACE_Process_Options  options;
    options.command_line(ACE_TEXT("http_sensor"));
    int ret;
    for(int i=0;i<ni_num_;++i){
    	if(!captor_[i]){
    		ACE_DEBUG((LM_ERROR,"captor not build.\n"));
    		exit(-1);
    	}
    	captor_pid[i]=ACE_Process_Manager::instance()->spawn(captor_[i],options);
    	if(captor_pid[i]<0){
    		ACE_DEBUG((LM_ERROR,"fork() captor process failed.\n"));
    		exit(-1);
    	}
    }
    if(stream_auditor_){
    	stream_auditor_pid=ACE_Process_Manager::instance()->spawn(stream_auditor_,options);
    	if(stream_auditor_pid<0){
    		ACE_DEBUG((LM_ERROR,"fork() Stream_auditor process failed.\n"));
    		exit(-1);
    	}
    }
    if(stream_dispatcher_){
    	stream_dispatcher_pid=ACE_Process_Manager::instance()->spawn(stream_dispatcher_,options);
    	if(stream_dispatcher_pid<0){
    		ACE_DEBUG((LM_ERROR,"fork() Stream_dispatcher process failed.\n"));
    		exit(-1);
    	}
    }
    if(outputer_){
    	outputer_pid=ACE_Process_Manager::instance()->spawn(outputer_,options);
    	if(outputer_pid<0){
    		ACE_DEBUG((LM_ERROR,"fork() outputer process failed.\n"));
    		exit(-1);
    	}
    }
    ACE_DEBUG((LM_DEBUG,"ACE_Process_Manager spawn child process successful.\n"));
    ret=ACE_Process_Manager::instance()->wait();
    if(ret<0){
    	ACE_DEBUG((LM_ERROR,"ACE_Process_Manager wait() error.\n"));
    }
	return 0;
}
int http_sensor::stop(){
	//_captor->stop();
	//_auditor->stop();
	//_outputor->stop();
	//send SIGHUP to child process to stop;
	for(int i=0;i<ni_num_;++i){
		ACE_Process_Manager::instance()->terminate(captor_pid[i],SIGHUP);
	}
	ACE_Process_Manager::instance()->terminate(stream_auditor_pid,SIGHUP);
	ACE_Process_Manager::instance()->terminate(stream_dispatcher_pid,SIGHUP);
	ACE_Process_Manager::instance()->terminate(outputer_pid,SIGHUP);
	return 0;
}

int http_sensor::read_config(){
	  int ret = 0;
//	  char value[512] = { 0 };
//	  Config config(config_file_);
//
//	  // get global section of config.
//	  if ((ret = config.get("global", "prefix", value, sizeof(value))) == 0) {
//	    if (setenv("PREFIX_HOME", value, 1) == -1) {
//	      ACE_DEBUG((LM_ERROR, " set enviroment failed, PREFIX_HOME=%s.\n", value));
//	    }
//
//	    strncpy(prefix_, value, sizeof(prefix_));
//	    strncpy(gather_file_, value, sizeof(gather_file_));
//	    strncat(gather_file_, "/etc/", sizeof(gather_file_));
//	  }
//
//	  if ((ret = config.get("global", "device", value, sizeof(value))) == 0) {
//	    device_id_ = atoi(value);
//	  }
//
//	  if ((ret = config.get("global", "gather", value, sizeof(value))) < 0) {
//	    ACE_DEBUG((LM_ERROR, " Not found gather of [global] in file %s.\n", config.config_file()));
//	    return ret;
//	  }
//
//	  snprintf(gather_file_, sizeof(gather_file_) - 1, "%s/etc/%s", prefix_, value);
//
//	  // get audit section of config.
//	  if ((ret = config.get("gather", "gather_log", value, sizeof(value))) == 0) {
//	    strncpy(log_file_, value, sizeof(log_file_));
//	  }
//
//	  snprintf(log_file_, sizeof(log_file_) - 1, "%s/log/%s", prefix_, value);
//
//	  if ((ret = config.get("gather", "gather_buffer", value, sizeof(value))) == 0) {
//	    buffer_size_ = atoi(value);
//	  }
//
//	  if ((ret = config.get("gather", "max_stream", value, sizeof(value))) == 0) {
//	    max_stream_ = atoi(value);
//	  }
//
//	  if ((ret = config.get("gather", "stream_timeout", value, sizeof(value))) == 0) {
//	    stream_timeout_ = atoi(value);
//	  }
//
//	  // get interface section of config.
//	  if ((ret = config.get("interface", "interface", value, sizeof(value))) < 0) {
//	    ACE_DEBUG((LM_ERROR, " Not found interface of [interface] in file %s.\n", config.config_file()));
//	    return ret;
//	  }
//
//	  ni_num_ = 0;
//	  const char *token = NULL;
//	  char *p = value;
//
//	  while ((token = strsep(&p, ", \t")) != NULL) {
//	    if (strlen(token) == 0) {
//	      continue;
//	    }
//
//	    strncpy(nis_[ni_num_], token, sizeof(nis_[ni_num_]));
//	    ni_num_++;
//	  }
//
//	  if ((ret = config.get("interface", "gather_filter", value, sizeof(value)))
//	      == 0) {
//	    strncpy(filter_, value, sizeof(filter_));
//	  }

	  return 0;
}
int http_sensor::load_config(const char* xml){
	if(!xml){
		return -1;
	}
	configure::global_config* config=
	configure::global_config::get_instance();
	if(!config){
		ACE_DEBUG((LM_ERROR,"get global_config instance error.\n"));
		return -1;
	}
    TiXmlDocument* pdoc=new TiXmlDocument(xml);
    if(!pdoc){
    	ACE_DEBUG((LM_ERROR,"create  xml document error.\n"));
    	return -1;
    }
    if(!pdoc->LoadFile()){
    	ACE_DEBUG((LM_ERROR,"load xmlfile  error  %s.\n",pdoc->ErrorDesc()));
    	delete pdoc;
    	return -1;
    }
    TiXmlElement * root=pdoc->RootElement();
    if(root){
    	 TiXmlElement* berkeleydb=root->FirstChildElement();
    	 if(!berkeleydb){
    		 delete pdoc;
    		 return -1;
    	 }
    	 TiXmlElement* bklchild=berkeleydb->FirstChildElement();
    	 for(;bklchild;bklchild=bklchild->NextSiblingElement()){
    		 const char* labelName=bklchild->Value();
    		 const char* labelValue=bklchild->GetText();

    			 if(strcmp(labelName,"db_home")==0){
    				 config->_bdb_capteddb_home=labelValue;
    				 continue;
    			 }
    			 if(strcmp(labelName,"cache_size")==0){
    				 config->_bdb_cache_size=atoi(labelValue);
    				 continue;
    			 }
    			 if(strcmp(labelName,"page_size")==0){
    				 config->_bdb_page_size=atoi(labelValue);
    				 continue;
    			 }
    			 if(strcmp(labelName,"deadlock_detect_val")==0){
    				 config->_bdb_deadlock_detect_val=atoi(labelValue);
    				 continue;
    			 }
    			 if(strcmp(labelName,"re_len")==0){
    				 config->_bdb_re_len=atoi(labelValue);
    				 continue;
    			 }
    			 if(strcmp(labelName,"q_extentsize")==0){
    				 config->_bdb_q_extent_size=atoi(labelValue);
    				 continue;
    			 }

    	 }
    	 TiXmlElement* psqldb=berkeleydb->NextSiblingElement();
    	 if(!psqldb){
    		 delete pdoc;
    		 return -1;
    	 }
         TiXmlElement* psqlchild=psqldb->FirstChildElement();
         for(;psqlchild;psqlchild=psqlchild->NextSiblingElement()){
        	 const char* labelName=psqlchild->Value();
        	 const char* labelValue=psqlchild->GetText();
    			 if(strcmp(labelName,"db_name")==0){
    				 config->_pgsl_db_name=labelValue;
    				 continue;
    			 }
    			 if(strcmp(labelName,"loginName")==0){
    				 config->_pgsl_loginName=labelValue;
    				 continue;
    			 }
    			 if(strcmp(labelName,"passWord")==0){
    				 config->_pgsl_passWord=labelValue;
    				 continue;
    			 }
    			 if(strcmp(labelName,"hostName")==0){
    				 config->_pgsl_hostName=labelValue;
    				 continue;
    			 }
    			 if(strcmp(labelName,"port")==0){
    				 config->_pgsl_port=atoi(labelValue);
    				 continue;
    			 }
    			 if(strcmp(labelName,"connTimeout")==0){
    				 config->_pgsl_conn_timeout=atoi(labelValue);
    				 continue;
    			 }

         }
      	 TiXmlElement* ssdb=berkeleydb->NextSiblingElement();
        	 if(!ssdb){
        		 delete pdoc;
        		 return -1;
        	 }
             TiXmlElement* ssdbchild=ssdb->FirstChildElement();
             for(;ssdbchild;ssdbchild=ssdbchild->NextSiblingElement()){
            	 const char* labelName=ssdbchild->Value();
                 const char* labelValue=ssdbchild->GetText();
        			 if(strcmp(labelName,"hostIP")==0){
        				 config->_ssdb_ip=labelValue;
        				 continue;
        			 }
        			 if(strcmp(labelName,"port")==0){
        				 config->_ssdb_port=atoi(labelValue);
        				 continue;
        			 }

             }
//             TiXmlElement* log=berkeleydb->NextSiblingElement();
//             if(!log){
//            	 return -1;
//             }
//             TiXmlElement* logchild=log->FirstChildElement();
//             for(;logchild;logchild=logchild->NextSiblingElement()){
//            	 TiXmlAttribute* att=logchild->FirstAttribute();
//            	 if(att){
//            		 if(strcmp(att->Name(),"log_home")==0){
//            			 config->_log_home=att->Value();
//            			 break;
//            		 }
//            	 }
//             }
             cout <<config->_bdb_outputdb_home<<endl;
             cout <<config->_bdb_capteddb_home<<endl;
             cout <<config->_bdb_cache_size<<endl;
             cout <<config->_bdb_page_size<<endl;
             cout <<config->_bdb_deadlock_detect_val<<endl;
             cout <<config->_bdb_re_len<<endl;
             cout <<config->_bdb_q_extent_size<<endl;
         	//end of fifo config

         	//postgreSQL config
             cout <<config->_pgsl_db_name<<endl;
             cout <<config->_pgsl_loginName<<endl;
             cout <<config->_pgsl_passWord<<endl;
             cout <<config->_pgsl_hostName<<endl;
             cout <<config->_pgsl_port<<endl;
             cout <<config->_pgsl_conn_timeout<<endl;
         	//end of postgreSQL config;

         	//ssdb config
             cout <<config->_ssdb_ip<<endl;
             cout <<config->_ssdb_port<<endl;
    }
    delete pdoc;
	return 0;
}
