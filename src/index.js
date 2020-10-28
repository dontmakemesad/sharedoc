import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import store from './app/store';
import { Provider } from 'react-redux';
import * as serviceWorker from './serviceWorker';

const toloadscript = async function (src){
  await new Promise(function (resolve,reject) {
    var script = document.createElement('script');
    script.type = 'text/javascript';
    script.async = true;
    script.src = src;
    script.onload = function (){
      resolve();
    }
    script.onerror = function (){
      reject();
    }
    document.head.appendChild(script);
  })
}

/////////////////////////////////////
async function runcode (){
  try {

    /**
     * 加载代码包
     * 具体请参考：https://github.com/signalapp/libsignal-protocol-javascript
     */
    await toloadscript('curve25519_concat.js');
    await toloadscript('libsignal-protocol.js');
    await toloadscript('plugin.js');
    await toloadscript('wordtext.js');
    console.log("加载库文件中")

  }
  catch(err) {
    console.log(err);
  }
  finally {
    console.log("加载完成")
    ReactDOM.render(
      <React.StrictMode>
        <Provider store={store}>
          <App />
        </Provider>
      </React.StrictMode>,
      document.getElementById('root')
    );
  }
}

runcode()

/////////////////////////////////////



// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
