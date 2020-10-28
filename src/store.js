import { createStore } from 'redux';
import rootReducer from './reducers/index';
import { setText,setId } from './action/index';

const store = createStore(rootReducer);

console.log(store.getState());

const unsubscribe = store.subscribe(()=>{
    console.log(store.getState())
});

store.dispatch(setText("123"))
store.dispatch(setId(21))

unsubscribe();