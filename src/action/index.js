/**
 * 修改文本
 * @param {*} text
 */

 export const setText = (text) => ({
     type:"setText",
     text
 })

 /**
  * 修改ID
  * @param {*} id 
  */
 export const setId = (id) => ({
     type:"setId",
     id
 })