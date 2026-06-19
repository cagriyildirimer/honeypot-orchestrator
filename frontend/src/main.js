const h = React.createElement;
const { useEffect, useState } = React;
import { App } from './components/App.js';

const rootNode = document.getElementById("app-root");
const rootElement = h(App);
ReactDOM.createRoot(rootNode).render(h(App));
