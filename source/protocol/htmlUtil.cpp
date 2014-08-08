/*
 * htmlUtil.cpp
 *
 *  Created on: 2014Äê8ÔÂ8ÈÕ
 *      Author: Administrator
 */

#include "htmlUtil.h"

htmlUtil::htmlUtil():_title("") {
	// TODO Auto-generated constructor stub
	_output=0;
}

htmlUtil::~htmlUtil() {
	// TODO Auto-generated destructor stub
	if(_output){
		gumbo_destroy_output(&kGumboDefaultOptions, _output);
		_output=0;
	}
}

int htmlUtil::parse_html(const char* input,int inputlen){
	if(!input||inputlen<=0){
		return -1;
	}
	_output= gumbo_parse_with_options(&kGumboDefaultOptions, input, inputlen);
	if(_output==0){
		return -1;
	}
	return 0;
}
string& htmlUtil::get_html_title(){
	const GumboNode* root=_output->root;
	assert(root->type == GUMBO_NODE_ELEMENT);
	  assert(root->v.element.children.length >= 2);
      if(root->type!=GUMBO_NODE_ELEMENT||root->v.element.children.length < 2){
    	  return "error";
      }
	  const GumboVector* root_children = &root->v.element.children;
	  GumboNode* head = NULL;
	  for (int i = 0; i < root_children->length; ++i) {
	    GumboNode* child = root_children->data[i];
	    if (child->type == GUMBO_NODE_ELEMENT &&
	        child->v.element.tag == GUMBO_TAG_HEAD) {
	      head = child;
	      break;
	    }
	  }
      if(head==0){
    	  return "no head";
      }

	  GumboVector* head_children = &head->v.element.children;
	  for (int i = 0; i < head_children->length; ++i) {
	    GumboNode* child = head_children->data[i];
	    if (child->type == GUMBO_NODE_ELEMENT &&
	        child->v.element.tag == GUMBO_TAG_TITLE) {
	      if (child->v.element.children.length != 1) {
	        return "<empty title>";
	      }
	      GumboNode* title_text = child->v.element.children.data[0];
	      //assert(title_text->type == GUMBO_NODE_TEXT);
	      if(title_text->type!=GUMBO_NODE_TEXT){
	    	  return "not text";
	      }
	      _title=title_text->v.text.text;
	      return _title;
	    }
	  }
	return "<no title found>";

}
