/*
 * httpsensor.h
 *
 *  Created on: 2014Äê7ÔÂ18ÈÕ
 *      Author: Administrator
 */
//added by xlf   2014/7/21


#ifndef HTTPSENSOR_H_
#define HTTPSENSOR_H_
#include <iostream>
#include <fstream>
#include"ace/Process.h"
#include"Captor.h"
//#include"logger.h"
#include"my_berkeleyDBbased_fifo.h"
#include"SSDB.h"
#include "GatherClassifier.h"
#include "StreamDispatcher.h"
#include "StreamAuditor.h"
#include "GatherOutputer.h"
#include <ace/Process_Manager.h>



#define GATHER_DEFAULT_LOG "/var/log/gather.log"
#define GATHER_DEFAULT_BUFFER 1024

class http_sensor {
public:

	 enum { MAX_CAPTOR = 16, DEFAULT_BUFFER = 1024, DEFAULT_STREAM = 1024 };
	http_sensor();
	virtual ~http_sensor();

public:



	  //! Create audit object.
	  int create();

	  //! Destroy audit object.
	  int destroy();

	  //! Run program, also run all children threads.
	  int run();

	  //! Stop program, also stop all children threads.
	  int stop();

	  //! Dump running information.
	  //void dump(std::ostream &os) const;
	  //void dump_stream(std::ostream &os) const;
	 // void dump_stream_ini(std::ostream &os) const;
	 // void dump_stream_xml(std::ostream &os) const;
	 // void dump_mac(std::ostream &os) const;

	  //! Dump sniffer configurations.
	  //void dump_config(std::ostream &os) const;

	  //! Dump network interface information.
	  //void dump_nis(std::ostream &os) const;

	  //! Read config value.
	  int read_config();

	 // int reload();

	  //! Set config file name.
	  /*!
	   * Mostly config file is nba.conf under NMA_HOME/etc.
	   * @param file is config file path. It must be full path.
	   */
	  void config_file(const char *file) {
	    strncpy(config_file_, file, sizeof(config_file_));
	  }

	  //! Get config file name.
	  const char *config_file() const {
	    return config_file_;
	  }

	  // enable or disable debug. Debug informatin will into log file.
	 // bool debug() const;
	 // void debug(bool flag);


private:
	//Captor<GatherClassifier>* _captor;
	//captor* _captor;
	//auditor* _auditor;
	//outputor* _outputor;
	//logger* _logger;
	//GatherClassifier *classifier_;
	//my_fifo<Frame>* _capted_fifo;
	//fifo* _output_fifo;


	  //! log file output stream.
	  std::ofstream outlog_;

	  //! Frame classifier.
	  GatherClassifier *classifier_;

	  //! Captors. Max number of Capters is 16.
	  Captor<GatherClassifier> *captor_[MAX_CAPTOR];

	  //! Stream dispatcher.
	  StreamDispatcher *stream_dispatcher_;

	  //! Stream auditors.
	  StreamAuditor *stream_auditor_;

	  //! Audit outputer.
	  GatherOutputer *outputer_;

	  //! Config items;
	  char config_file_[256];

	  //! Items in config file. Erase it.
	  char log_file_[256];
	  int buffer_size_;
	  int max_stream_;
	  int stream_timeout_;

	  int device_id_;
	  char prefix_[256];
	  char gather_file_[256];

	  //! Network Interface (NI) number. Max number is 16.
	  int ni_num_;

	  //! Network Interfaces' name, such as "eth0, eth1" etc.
	  char nis_[MAX_CAPTOR][32];

	  //! Network Interface filter for capture. Some thing as "TCP or UDP".
	  char filter_[256];

	  //! Information.
	  time_t startup_;

	  pid_t captor_pid[MAX_CAPTOR];
	  pid_t stream_auditor_pid;
	  pid_t stream_dispatcher_pid;
	  pid_t outputer_pid;

};

#endif /* HTTPSENSOR_H_ */
