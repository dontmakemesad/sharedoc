const { act } = require("react-dom/test-utils");

export const reducerssetid = (state={id:0},action)=>{
    switch (action.type) {
        case "setId":
            return{
                id: action.id
            }
    
        default:
            return state;
    }
}