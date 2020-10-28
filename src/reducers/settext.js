const { act } = require("react-dom/test-utils");


export const reducerssettext = (state={text: "action"},action)=>{
    switch (action.type) {
        case "setText":
            return{
                text: action.text
            }
        default:
            return state;
    }
}